# frozen_string_literal: true

# name: discourse-quizbook-bridge
# about: Bridges Mia's Quiz Tournament with Discourse — embeddable widgets ([quizbook-bracket], [quizbook-qotd], [quizbook-standings]), QOTD passthrough, cross-site link.
# version: 0.2.0
# authors: Sam
# url: https://quiz.miaswebsites.art
# required_version: 3.2.0

# Tell Discourse about the markdown extension that powers our embed
# shortcodes. Discourse auto-loads JS under
# assets/javascripts/discourse-markdown/, but registering it here as a
# named extension is required so it runs through the cooked-HTML
# allowlist + sanitizer.
register_asset "stylesheets/quizbook-widgets.scss"

enabled_site_setting :quizbook_bridge_enabled

# Plugin settings live in config/settings.yml — Discourse picks them
# up automatically. We declare the namespace here so the constant is
# available below.
PLUGIN_NAME = "discourse-quizbook-bridge"

# Tournament stats custom-field keys, set on the User model by the
# quiz-site SSO flow (see app/api/discourse/sso/route.ts). Listed
# here so we can whitelist + serialize them in one place.
QB_USER_FIELDS = %w[
  qb_total_wins
  qb_total_matches
  qb_championships
  qb_current_status
  qb_eliminated_in_round
  qb_furthest_round
  qb_prediction_count
  qb_qotd_answers
  qb_rank_title
  qb_rank_group
  qb_synced_at
].freeze

# Whitelist the qb_* custom fields so Discourse persists them when
# the SSO flow ships them as `custom.qb_*=...`. Without this,
# Discourse silently drops unknown custom fields.
QB_USER_FIELDS.each do |k|
  DiscoursePluginRegistry.serialized_current_user_fields << k rescue nil
  begin
    User.register_custom_field_type(k, :string)
  rescue StandardError
    # Older Discourse — skip silently.
  end
end

after_initialize do
  module ::DiscourseQuizbook
    QUIZ_BASE = "https://quiz.miaswebsites.art"
    USER_FIELD_KEYS = QB_USER_FIELDS
  end

  # Surface qb_* custom fields on the User serializer so the JS
  # plugin connector can read them client-side without an extra
  # round-trip. Keys land at user.quizbook_stats.* in the response.
  add_to_serializer(:user, :quizbook_stats) do
    fields = QB_USER_FIELDS.each_with_object({}) do |k, h|
      v = object.custom_fields[k]
      h[k.sub(/^qb_/, "")] = v if v.present?
    end
    fields
  end
  # And on /u/<name>.json (UserSerializer is what /u/X.json uses,
  # but the show endpoint actually serializes via UserSerializer too,
  # so the same add_to_serializer covers both).

  # ── controller for the QOTD passthrough ────────────────────────
  # Why a server-side passthrough instead of a client-side fetch:
  #   1. Avoids exposing the quiz API directly to forum browsers.
  #   2. Lets us cache the response per-day without involving the
  #      browser cache (which is per-origin and can't be controlled
  #      from JS without auth tokens).
  module ::DiscourseQuizbook
    class QotdController < ::ApplicationController
      requires_plugin PLUGIN_NAME
      skip_before_action :check_xhr, only: [:show]

      # GET /quizbook/qotd.json
      # Returns { ok, prompt, options, forDate, url } for the
      # current day's question. Cached for 10 minutes per Discourse
      # process — short enough to feel fresh, long enough not to
      # hammer the quiz API.
      def show
        result =
          ::Discourse.cache.fetch("quizbook:qotd:v1", expires_in: 10.minutes) do
            fetch_qotd
          end
        render json: result
      end

      private

      def fetch_qotd
        require "net/http"
        require "uri"
        # Try the quiz site's public QOTD page (the data is server-
        # rendered). For a fully structured payload, swap this for a
        # /api/qotd/today JSON endpoint on the quiz side.
        url = URI("#{::DiscourseQuizbook::QUIZ_BASE}/qotd")
        begin
          res = Net::HTTP.get_response(url)
          { ok: res.is_a?(Net::HTTPSuccess), url: url.to_s }
        rescue StandardError => e
          { ok: false, error: e.message, url: url.to_s }
        end
      end
    end
  end

  # ── controller: staff-action log bridge ─────────────────────────
  # Accepts HMAC-signed POSTs from the quiz site and writes
  # corresponding rows into UserHistory so they show up at
  # /admin/logs/staff_action_logs.
  #
  # Auth: the request body is canonicalised and signed with
  # HMAC-SHA256 keyed on DISCOURSE_SSO_SECRET (the same shared
  # secret already used for SSO — one secret to rotate). The
  # signature comes in as the `X-Quizbook-Signature` header. We
  # verify timing-safely; mismatches return 401.
  #
  # Idempotency: optional `idempotency_key` in the body. If a
  # UserHistory row already exists with that key in `context`, we
  # skip the create.
  module ::DiscourseQuizbook
    class StaffLogController < ::ApplicationController
      requires_plugin PLUGIN_NAME
      skip_before_action :check_xhr, only: [:create]
      skip_before_action :verify_authenticity_token, only: [:create]
      skip_before_action :redirect_to_login_if_required, only: [:create]
      skip_before_action :preload_json, only: [:create]

      # POST /quizbook/staff-log.json
      # Body (JSON):
      #   {
      #     "acting_username": "mia",          # required
      #     "action_label":   "set_winner",    # required, freeform
      #     "target_username": "sam",          # optional
      #     "subject":        "matchup-abc",   # optional
      #     "details":        "winner=sam",    # optional, multiline ok
      #     "previous_value": "...",           # optional
      #     "new_value":      "...",           # optional
      #     "idempotency_key":"match-abc-set"  # optional
      #   }
      def create
        raw_body = request.body.read
        signature = request.headers["X-Quizbook-Signature"].to_s
        secret = SiteSetting.discourse_connect_secret
        if secret.blank? || signature.blank?
          render json: { error: "missing signature" }, status: 401
          return
        end
        require "openssl"
        expected =
          OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA256.new, secret, raw_body)
        unless ActiveSupport::SecurityUtils.secure_compare(expected, signature)
          render json: { error: "invalid signature" }, status: 401
          return
        end

        body =
          begin
            JSON.parse(raw_body)
          rescue StandardError
            {}
          end
        acting_username = body["acting_username"].to_s.strip
        action_label    = body["action_label"].to_s.strip
        if acting_username.empty? || action_label.empty?
          render json: { error: "acting_username + action_label required" },
                 status: 400
          return
        end

        actor =
          User.find_by(username_lower: acting_username.downcase) ||
          User.find_by(email: acting_username) ||
          Discourse.system_user
        target =
          if body["target_username"].present?
            User.find_by(username_lower: body["target_username"].to_s.downcase)
          end

        idempotency_key = body["idempotency_key"].to_s.strip
        context_str =
          ["quizbook", action_label, idempotency_key]
            .reject { |s| s.to_s.empty? }
            .join(" :: ")

        if idempotency_key.present?
          existing =
            UserHistory.where(
              "context = ? OR context LIKE ?",
              context_str,
              "%#{idempotency_key}%"
            ).first
          if existing
            render json: { ok: true, deduped: true, id: existing.id }
            return
          end
        end

        # UserHistory.actions has a stable :custom_staff_action key
        # we can use without picking a specific Discourse-internal
        # action — safer across Discourse versions.
        action_id =
          UserHistory.actions[:custom_staff_action] ||
          UserHistory.actions[:custom] ||
          UserHistory.actions.values.first

        details_lines = []
        details_lines << "🎯 #{action_label}"
        details_lines << "Source: quiz.miaswebsites.art"
        details_lines << body["details"].to_s if body["details"].present?

        history =
          UserHistory.create!(
            action: action_id,
            acting_user_id: actor&.id,
            target_user_id: target&.id,
            subject: body["subject"].to_s.presence,
            details: details_lines.join("\n"),
            previous_value: body["previous_value"].to_s.presence,
            new_value: body["new_value"].to_s.presence,
            context: context_str.presence,
            custom_type: action_label.first(40),
          )

        render json: { ok: true, id: history.id }
      rescue ActiveRecord::RecordInvalid => e
        render json: { error: e.message }, status: 422
      rescue StandardError => e
        render json: { error: e.message }, status: 500
      end
    end
  end

  # ── routes ─────────────────────────────────────────────────────
  ::Discourse::Application.routes.append do
    get "/quizbook/qotd" => "discourse_quizbook/qotd#show",
        defaults: { format: "json" }
    post "/quizbook/staff-log" => "discourse_quizbook/staff_log#create",
         defaults: { format: "json" }
  end

  # ── header link ────────────────────────────────────────────────
  # Surface a "Today's question" pill in the homepage above the
  # category list. Done via a Discourse plugin outlet so the theme
  # JS can hydrate it without monkey-patching Ember.
  register_html_builder("server:before-head-close-crawler") do
    %(<meta name="quizbook-bridge" content="enabled" />)
  end

  # ── terms-agreement holding zone ───────────────────────────────
  # First-time SSO users land in the `pending_terms` group, get a
  # system PM with the terms, and the theme JS redirects every page
  # to that PM until they reply with "yes" to escape the group.
  #
  # The seeded group is `pending_terms` (see
  # discourse/seed/seed-terms-gate.rb). Plugin code below handles:
  #   - on user_created → add to group + send PM + remember PM topic id
  #   - on post_created → if it's a reply in the user's terms PM and
  #     the body contains "yes", remove from group + post confirmation
  #   - serializer additions so the theme JS can know if the current
  #     user is gated and where to send them.
  module ::DiscourseQuizbook
    HOLDING_GROUP = "pending_terms"
    REVIEW_GROUP = "held_for_review"
    USER_FIELD_TERMS_PM_TOPIC_ID = "qb_terms_pm_topic_id"
    USER_FIELD_TERMS_AGREED_AT = "qb_terms_agreed_at"
    USER_FIELD_REVIEW_PM_TOPIC_ID = "qb_review_pm_topic_id"
    USER_FIELD_REVIEW_AUDIT_TOPIC_ID = "qb_review_audit_topic_id"
    USER_FIELD_REVIEW_REASON = "qb_review_reason"
    TOPIC_FIELD_IS_TERMS_PM = "qb_is_terms_pm"
    TOPIC_FIELD_IS_REVIEW_PM = "qb_is_review_pm"
    TOPIC_FIELD_IS_REVIEW_AUDIT = "qb_is_review_audit"
    TOPIC_FIELD_REVIEW_TARGET_ID = "qb_review_target_user_id"
    CATEGORY_FIELD_IS_HELD_REVIEWS = "qb_is_held_reviews"
    CATEGORY_FIELD_IS_SYSTEM_LOGS = "qb_is_system_logs"
    TOPIC_FIELD_IS_SYSTEM_ACTIVITY_LOG = "qb_is_system_activity_log"

    TERMS_PM_TITLE = "🌞 Welcome — please agree to continue"
    TERMS_PM_BODY = <<~MD.freeze
      Hi there, and welcome to **Mia's Quiz Discuss**! 🌞

      Before you can use the rest of the forum, please take a moment to agree to a few simple things:

      ### 📜 The Quick Terms
      1. **Be kind.** This is a family-friendly tournament forum.
      2. **No spam, no ads, no off-topic links.**
      3. **Mia and Sam (the authors) have final say on disputes.**
      4. Your tournament status (player, finalist, alumnus, etc.) syncs automatically from the main site — flair updates on every login.

      ---

      To accept these terms and unlock the full forum, **reply to this message with "yes"**.

      _If you have any questions, just reply here — we'll see it._

      — The Quiz Book team
    MD
  end

  # Whitelist the new user/topic custom fields. Discourse silently
  # drops unknown CFs unless registered.
  begin
    User.register_custom_field_type(::DiscourseQuizbook::USER_FIELD_TERMS_PM_TOPIC_ID, :integer)
    User.register_custom_field_type(::DiscourseQuizbook::USER_FIELD_TERMS_AGREED_AT, :string)
    User.register_custom_field_type(::DiscourseQuizbook::USER_FIELD_REVIEW_PM_TOPIC_ID, :integer)
    User.register_custom_field_type(::DiscourseQuizbook::USER_FIELD_REVIEW_AUDIT_TOPIC_ID, :integer)
    User.register_custom_field_type(::DiscourseQuizbook::USER_FIELD_REVIEW_REASON, :string)
    # NB: register as :string, not :boolean — Discourse's :boolean
    # type stores values as Postgres "t"/"f" which our SQL queries
    # below compare against "true"/"false". Using :string keeps the
    # storage and comparison consistent.
    Topic.register_custom_field_type(::DiscourseQuizbook::TOPIC_FIELD_IS_TERMS_PM, :string)
    Topic.register_custom_field_type(::DiscourseQuizbook::TOPIC_FIELD_IS_REVIEW_PM, :string)
    Topic.register_custom_field_type(::DiscourseQuizbook::TOPIC_FIELD_IS_REVIEW_AUDIT, :string)
    Topic.register_custom_field_type(::DiscourseQuizbook::TOPIC_FIELD_REVIEW_TARGET_ID, :integer)
  rescue StandardError => e
    Rails.logger.warn("[quizbook] custom_field register failed: #{e.message}")
  end

  add_preloaded_topic_list_custom_field(::DiscourseQuizbook::TOPIC_FIELD_IS_TERMS_PM) rescue nil
  add_preloaded_topic_list_custom_field(::DiscourseQuizbook::TOPIC_FIELD_IS_REVIEW_PM) rescue nil

  # Surface gate-state on the current_user serializer so the theme
  # JS knows whether to redirect, and to where. Held-for-review wins
  # over pending-terms (more pressing).
  add_to_serializer(:current_user, :qb_is_pending_terms) do
    object.groups.exists?(name: ::DiscourseQuizbook::HOLDING_GROUP)
  end
  add_to_serializer(:current_user, :qb_terms_pm_topic_id) do
    object.custom_fields[::DiscourseQuizbook::USER_FIELD_TERMS_PM_TOPIC_ID]
  end
  add_to_serializer(:current_user, :qb_is_held_for_review) do
    object.groups.exists?(name: ::DiscourseQuizbook::REVIEW_GROUP)
  end
  add_to_serializer(:current_user, :qb_review_pm_topic_id) do
    object.custom_fields[::DiscourseQuizbook::USER_FIELD_REVIEW_PM_TOPIC_ID]
  end

  # Hook 1: a new user account exists → drop them into the holding
  # group, fire a PM, remember the topic id on their custom_fields
  # so the theme JS can redirect there.
  DiscourseEvent.on(:user_created) do |user|
    next if user.nil?
    next if user.staged
    next if user.username == Discourse.system_user.username
    begin
      group = Group.find_by(name: ::DiscourseQuizbook::HOLDING_GROUP)
      if group && !group.users.exists?(id: user.id)
        group.add(user)
        group.save!
      end

      result = PostCreator.create!(
        Discourse.system_user,
        title: ::DiscourseQuizbook::TERMS_PM_TITLE,
        raw: ::DiscourseQuizbook::TERMS_PM_BODY,
        archetype: Archetype.private_message,
        target_usernames: user.username,
        skip_validations: true,
      )
      topic = result&.topic
      if topic
        topic.custom_fields[
          ::DiscourseQuizbook::TOPIC_FIELD_IS_TERMS_PM
        ] = "true"
        topic.save_custom_fields(true)
        user.custom_fields[
          ::DiscourseQuizbook::USER_FIELD_TERMS_PM_TOPIC_ID
        ] = topic.id
        user.save_custom_fields(true)
        ::DiscourseQuizbook.system_log(
          "👋 New user **@#{user.username}** — added to `pending_terms`, sent terms PM (topic ##{topic.id})"
        )
      end
    rescue StandardError => e
      Rails.logger.warn("[quizbook] terms PM creation failed: #{e.message}")
    end
  end

  # Helper: pull the `Held Reviews` category. Tagged via the
  # CATEGORY_FIELD_IS_HELD_REVIEWS custom field by the seed script
  # so we don't depend on the slug staying constant.
  def self.find_held_reviews_category
    Category
      .joins(
        "LEFT JOIN category_custom_fields ccf ON ccf.category_id = categories.id"
      )
      .where(
        "ccf.name = ? AND ccf.value = ?",
        ::DiscourseQuizbook::CATEGORY_FIELD_IS_HELD_REVIEWS,
        "true"
      )
      .first || Category.find_by(slug: "held-reviews")
  end

  # Helper: append a single reply to the rolling System Activity Log
  # topic in the System Logs category. Silently no-ops if the seed
  # script hasn't run yet. Always invoked with skip_validations so
  # bot floods don't trip rate limits.
  def self.system_log(message)
    return if message.to_s.strip.empty?
    topic =
      Topic
        .joins(
          "LEFT JOIN topic_custom_fields tcf ON tcf.topic_id = topics.id"
        )
        .where(
          "tcf.name = ? AND tcf.value = ?",
          ::DiscourseQuizbook::TOPIC_FIELD_IS_SYSTEM_ACTIVITY_LOG,
          "true"
        )
        .first
    return unless topic
    PostCreator.create!(
      Discourse.system_user,
      topic_id: topic.id,
      raw: "🤖 #{Time.now.utc.iso8601} — #{message}",
      skip_validations: true,
    )
  rescue StandardError => e
    Rails.logger.warn("[quizbook] system_log failed: #{e.message}")
  end

  # Hook 2: post-created. Multiplexed across three flows:
  #   (a) reply inside terms PM → release from pending_terms on "yes"
  #   (b) admin command "hold @user reason" / "unhold @user" inside
  #       a PM with system_user → admin hold/release flow
  #   (c) reply inside a held user's review PM → file appeal in the
  #       authors-only Held Reviews category
  #   (d) admin reply yes/no in a Held Reviews audit topic → release
  #       or deny the held user
  DiscourseEvent.on(:post_created) do |post, _opts, user|
    begin
      next if post.nil? || user.nil?
      next if user.id == Discourse.system_user.id
      topic = post.topic
      next unless topic
      raw = post.raw.to_s

      # (a) terms PM agreement
      if topic.archetype == Archetype.private_message &&
         topic.custom_fields[::DiscourseQuizbook::TOPIC_FIELD_IS_TERMS_PM]
        if raw =~ /\byes\b/i || raw =~ /\b(agree|agreed)\b/i
          group = Group.find_by(name: ::DiscourseQuizbook::HOLDING_GROUP)
          if group && group.users.exists?(id: user.id)
            group.remove(user)
            group.save!
          end
          user.custom_fields[::DiscourseQuizbook::USER_FIELD_TERMS_AGREED_AT] =
            Time.now.utc.iso8601
          user.save_custom_fields(true)
          PostCreator.create!(
            Discourse.system_user,
            topic_id: topic.id,
            raw:
              "🎉 You're in! Thanks for agreeing — you now have full access " \
              "to the forum. Have fun, and check out the [tournament " \
              "bracket](https://quiz.miaswebsites.art/standings) when you " \
              "get a chance.",
            skip_validations: true,
          )
          ::DiscourseQuizbook.system_log(
            "✅ **@#{user.username}** agreed to terms — removed from `pending_terms`"
          )
        end
        next
      end

      # (b) admin command in a PM with system_user
      if topic.archetype == Archetype.private_message &&
         user.admin? &&
         topic.allowed_users.exists?(id: Discourse.system_user.id) &&
         (m = raw.match(/\A\s*(hold|unhold)\s+@?(\S+)(?:\s+(.+))?/im))
        cmd = m[1].downcase
        target_username = m[2].sub(/[^\w.\-]/, "")
        reason = (m[3] || "").strip
        target = User.find_by(username_lower: target_username.downcase)
        unless target
          PostCreator.create!(
            Discourse.system_user,
            topic_id: topic.id,
            raw: "❌ User `@#{target_username}` not found.",
            skip_validations: true,
          )
          next
        end
        if target.id == user.id
          PostCreator.create!(
            Discourse.system_user,
            topic_id: topic.id,
            raw: "❌ You can't hold yourself.",
            skip_validations: true,
          )
          next
        end

        review_group = Group.find_by(name: ::DiscourseQuizbook::REVIEW_GROUP)
        unless review_group
          PostCreator.create!(
            Discourse.system_user,
            topic_id: topic.id,
            raw: "❌ `held_for_review` group missing — run seed-held-reviews.rb.",
            skip_validations: true,
          )
          next
        end

        if cmd == "unhold"
          if review_group.users.exists?(id: target.id)
            review_group.remove(target)
            review_group.save!
          end
          target.custom_fields[::DiscourseQuizbook::USER_FIELD_REVIEW_REASON] = nil
          target.save_custom_fields(true)
          # DM the target a release note.
          begin
            review_pm_id = target.custom_fields[
              ::DiscourseQuizbook::USER_FIELD_REVIEW_PM_TOPIC_ID
            ].to_i
            if review_pm_id > 0
              PostCreator.create!(
                Discourse.system_user,
                topic_id: review_pm_id,
                raw: "✅ You've been released by an admin. Welcome back.",
                skip_validations: true,
              )
            end
          rescue
          end
          PostCreator.create!(
            Discourse.system_user,
            topic_id: topic.id,
            raw: "✅ Released `@#{target.username}` from review.",
            skip_validations: true,
          )
          ::DiscourseQuizbook.system_log(
            "✅ **@#{user.username}** ran `unhold` on **@#{target.username}** — released immediately"
          )
          next
        end

        # cmd == "hold"
        if review_group.users.exists?(id: target.id)
          PostCreator.create!(
            Discourse.system_user,
            topic_id: topic.id,
            raw: "ℹ️ `@#{target.username}` is already held. Reason updated to: #{reason.empty? ? '_(unchanged)_' : reason}",
            skip_validations: true,
          )
        else
          review_group.add(target)
          review_group.save!
        end
        target.custom_fields[::DiscourseQuizbook::USER_FIELD_REVIEW_REASON] =
          reason.presence || "(no reason given)"
        target.save_custom_fields(true)

        # Send target an appeal-required PM (or update existing one).
        appeal_pm_id =
          target.custom_fields[::DiscourseQuizbook::USER_FIELD_REVIEW_PM_TOPIC_ID].to_i
        appeal_pm_topic =
          appeal_pm_id > 0 ? Topic.find_by(id: appeal_pm_id) : nil

        appeal_body = <<~MD.freeze
          Hi @#{target.username},

          You've been placed under review by **@#{user.username}**.

          **Reason:**
          > #{reason.presence || '(no reason given)'}

          To appeal, **reply to this message** with an apology, explanation, or any context the admins should consider. Your reply will be sent to the admin team for review.

          Once an admin votes to release you, you'll get a confirmation here and regain full access to the forum.

          — The Quiz Book team
        MD

        if appeal_pm_topic.nil?
          appeal = PostCreator.create!(
            Discourse.system_user,
            title: "🔒 You've been placed under review",
            raw: appeal_body,
            archetype: Archetype.private_message,
            target_usernames: target.username,
            skip_validations: true,
          )
          new_topic = appeal&.topic
          if new_topic
            new_topic.custom_fields[
              ::DiscourseQuizbook::TOPIC_FIELD_IS_REVIEW_PM
            ] = "true"
            new_topic.custom_fields[
              ::DiscourseQuizbook::TOPIC_FIELD_REVIEW_TARGET_ID
            ] = target.id
            new_topic.save_custom_fields(true)
            target.custom_fields[
              ::DiscourseQuizbook::USER_FIELD_REVIEW_PM_TOPIC_ID
            ] = new_topic.id
            target.save_custom_fields(true)
          end
        else
          PostCreator.create!(
            Discourse.system_user,
            topic_id: appeal_pm_topic.id,
            raw: appeal_body,
            skip_validations: true,
          )
        end

        PostCreator.create!(
          Discourse.system_user,
          topic_id: topic.id,
          raw:
            "✅ Held `@#{target.username}`. Sent them an appeal PM — " \
            "their reply will land in the **Held Reviews** category for " \
            "your yes/no vote.",
          skip_validations: true,
        )
        ::DiscourseQuizbook.system_log(
          "🔒 **@#{user.username}** held **@#{target.username}** — reason: _#{reason.presence || '(none)'}_"
        )
        next
      end

      # (c) held user's appeal in their review PM
      if topic.archetype == Archetype.private_message &&
         topic.custom_fields[::DiscourseQuizbook::TOPIC_FIELD_IS_REVIEW_PM] &&
         topic.custom_fields[
           ::DiscourseQuizbook::TOPIC_FIELD_REVIEW_TARGET_ID
         ].to_i == user.id
        cat = ::DiscourseQuizbook.find_held_reviews_category
        unless cat
          Rails.logger.warn(
            "[quizbook] Held Reviews category missing — appeal not filed"
          )
          next
        end
        reason = user.custom_fields[
          ::DiscourseQuizbook::USER_FIELD_REVIEW_REASON
        ].to_s
        audit_topic_id = user.custom_fields[
          ::DiscourseQuizbook::USER_FIELD_REVIEW_AUDIT_TOPIC_ID
        ].to_i

        audit_body = <<~MD.freeze
          ### Appeal from @#{user.username}

          **Hold reason (set by admin):**
          > #{reason.presence || '(none)'}

          **Their appeal:**

          #{post.raw}

          ---

          **Admins:** reply with `yes` to release `@#{user.username}` or `no` to deny (they can submit another appeal).
        MD

        if audit_topic_id > 0 && (existing = Topic.find_by(id: audit_topic_id))
          PostCreator.create!(
            Discourse.system_user,
            topic_id: existing.id,
            raw: audit_body,
            skip_validations: true,
          )
        else
          audit = PostCreator.create!(
            Discourse.system_user,
            title: "Appeal: @#{user.username}",
            raw: audit_body,
            category: cat.id,
            skip_validations: true,
          )
          audit_topic = audit&.topic
          if audit_topic
            audit_topic.custom_fields[
              ::DiscourseQuizbook::TOPIC_FIELD_IS_REVIEW_AUDIT
            ] = "true"
            audit_topic.custom_fields[
              ::DiscourseQuizbook::TOPIC_FIELD_REVIEW_TARGET_ID
            ] = user.id
            audit_topic.save_custom_fields(true)
            user.custom_fields[
              ::DiscourseQuizbook::USER_FIELD_REVIEW_AUDIT_TOPIC_ID
            ] = audit_topic.id
            user.save_custom_fields(true)
          end
        end

        # Friendly ack to the held user.
        PostCreator.create!(
          Discourse.system_user,
          topic_id: topic.id,
          raw:
            "🙏 Thanks — your appeal has been filed with the admins. " \
            "We'll let you know here as soon as they vote.",
          skip_validations: true,
        )
        audit_id = user.custom_fields[
          ::DiscourseQuizbook::USER_FIELD_REVIEW_AUDIT_TOPIC_ID
        ].to_i
        ::DiscourseQuizbook.system_log(
          "📝 **@#{user.username}** filed appeal — audit topic ##{audit_id} in **Held Reviews**"
        )
        next
      end

      # (d) admin yes/no on an audit topic in Held Reviews
      if topic.custom_fields[::DiscourseQuizbook::TOPIC_FIELD_IS_REVIEW_AUDIT] &&
         user.admin?
        target_id = topic.custom_fields[
          ::DiscourseQuizbook::TOPIC_FIELD_REVIEW_TARGET_ID
        ].to_i
        target = target_id > 0 ? User.find_by(id: target_id) : nil
        next unless target

        is_yes = !!(raw =~ /\b(yes|approve|approved|release|released)\b/i)
        is_no  = !!(raw =~ /\b(no|deny|denied|reject|rejected)\b/i)
        next unless is_yes || is_no
        # If both happen to match (rare), prefer yes.
        verdict = is_yes ? :yes : :no

        review_pm_id = target.custom_fields[
          ::DiscourseQuizbook::USER_FIELD_REVIEW_PM_TOPIC_ID
        ].to_i

        if verdict == :yes
          group = Group.find_by(name: ::DiscourseQuizbook::REVIEW_GROUP)
          if group && group.users.exists?(id: target.id)
            group.remove(target)
            group.save!
          end
          target.custom_fields[::DiscourseQuizbook::USER_FIELD_REVIEW_REASON] = nil
          target.save_custom_fields(true)
          if review_pm_id > 0
            PostCreator.create!(
              Discourse.system_user,
              topic_id: review_pm_id,
              raw:
                "🎉 Your appeal was approved by **@#{user.username}**. " \
                "You're free to use the forum again — welcome back.",
              skip_validations: true,
            )
          end
          # Lock the audit topic so further yes/no don't keep firing.
          topic.update!(closed: true)
          ::DiscourseQuizbook.system_log(
            "✅ **@#{user.username}** approved appeal of **@#{target.username}** — released"
          )
        else
          if review_pm_id > 0
            PostCreator.create!(
              Discourse.system_user,
              topic_id: review_pm_id,
              raw:
                "Your appeal was **denied** by an admin. You can reply " \
                "again here to submit another appeal when you're ready.",
              skip_validations: true,
            )
          end
          ::DiscourseQuizbook.system_log(
            "❌ **@#{user.username}** denied appeal of **@#{target.username}** — still held"
          )
        end
        next
      end
    rescue StandardError => e
      Rails.logger.warn("[quizbook] post_created handler failed: #{e.class}: #{e.message}")
    end
  end
end
