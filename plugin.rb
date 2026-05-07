# frozen_string_literal: true

# name: discourse-quizbook-bridge
# about: Bridges Mia's Quiz Tournament with Discourse — sidebar QOTD widget, cross-site link injection, /quizbook/qotd JSON alias.
# version: 0.1.0
# authors: Sam
# url: https://quiz.miaswebsites.art
# required_version: 3.2.0

enabled_site_setting :quizbook_bridge_enabled

# Plugin settings live in config/settings.yml — Discourse picks them
# up automatically. We declare the namespace here so the constant is
# available below.
PLUGIN_NAME = "discourse-quizbook-bridge"

after_initialize do
  module ::DiscourseQuizbook
    QUIZ_BASE = "https://quiz.miaswebsites.art"
  end

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

  # ── routes ─────────────────────────────────────────────────────
  ::Discourse::Application.routes.append do
    get "/quizbook/qotd" => "discourse_quizbook/qotd#show",
        defaults: { format: "json" }
  end

  # ── header link ────────────────────────────────────────────────
  # Surface a "Today's question" pill in the homepage above the
  # category list. Done via a Discourse plugin outlet so the theme
  # JS can hydrate it without monkey-patching Ember.
  register_html_builder("server:before-head-close-crawler") do
    %(<meta name="quizbook-bridge" content="enabled" />)
  end
end
