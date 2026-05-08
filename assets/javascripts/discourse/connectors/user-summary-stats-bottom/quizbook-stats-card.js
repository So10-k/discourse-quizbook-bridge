// Connector that decides whether to render the picture-book stats
// card on /u/<name>/summary. Always shows if the user has any
// qb_* custom fields populated. Hides cleanly for users who have
// never logged into the forum via SSO (e.g. discobot, system).

export default {
  shouldRender(args, component) {
    const stats = args && args.model && args.model.quizbook_stats;
    if (!stats) return false;
    // True when at least one numeric stat is non-zero or rank_title is set.
    return (
      !!stats.rank_title ||
      Number(stats.total_matches || 0) > 0 ||
      Number(stats.championships || 0) > 0 ||
      Number(stats.prediction_count || 0) > 0
    );
  },
};
