# coding: utf-8
from pathlib import Path
path = Path("src/server-admin.js")
text = path.read_text(encoding="utf-8")
start_marker = 'app.get("/campaigns/:id/report/v2"'
end_marker = 'app.get("/campaigns/:id/report",'
start = text.find(start_marker)
end = text.find(end_marker)
if start == -1 or end == -1 or end <= start:
    raise SystemExit("markers not found")
new_block = """app.get(\"/campaigns/:id/report/v2\", checkAuth, async (req, res) => {
  const campId = req.params.id;
  const preset = req.query.preset || \"today\"; // today/this_week/this_month/this_year/all/custom
  const now = new Date();

  const parseDate = (s) => {
    const d = new Date(s);
    return isNaN(d) ? null : d;
  };
  const startOfDay = (d) =>
    new Date(d.getFullYear(), d.getMonth(), d.getDate());
  const rangeLabelText = (s, e) => {
    const endDisplay = new Date(e);
    endDisplay.setDate(endDisplay.getDate() - 1);
    return `${s.toLocaleDateString(\"vi-VN\")} - ${endDisplay.toLocaleDateString(\"vi-VN\")}`;
  };
  const presetLabels = {
    today: \"Hôm nay\",
    this_week: \"Tuần này\",
    this_month: \"Tháng này\",
    this_year: \"Năm nay\",
    all: \"Tất cả\",
    custom: \"Tùy chọn\",
  };
  const bucketByPreset = {
    today: \"hour\",
    this_week: \"day\",
    this_month: \"week\",
    this_year: \"month\",
    all: \"month\",
    custom: \"day\",
  };

  const rCamp = await db.query(`SELECT * FROM campaigns WHERE id=$1`, [
    campId,
  ]);
  if (!rCamp.rowCount) return res.redirect(\"/redirect\");
  const camp = rCamp.rows[0];

  let start;
  let end;
  let bucketType = bucketByPreset[preset] || \"hour\";

  if (preset === \"this_week\") {
    const today = startOfDay(now);
    const dow = today.getDay();
    const diff = dow === 0 ? -6 : 1 - dow; // Monday start
    start = new Date(today);
    start.setDate(start.getDate() + diff);
    end = new Date(start);
    end.setDate(start.getDate() + 7);
  } else if (preset === \"this_month\") {
    start = new Date(now.getFullYear(), now.getMonth(), 1);
    end = new Date(now.getFullYear(), now.getMonth() + 1, 1);
  } else if (preset === \"this_year\") {
    start = new Date(now.getFullYear(), 0, 1);
    end = new Date(now.getFullYear() + 1, 0, 1);
  } else if (preset === \"all\") {
    const earliest = await db.query(
      `SELECT MIN(created_at) AS min_date FROM traffic_logs WHERE campaign_id=$1`,
      [campId]
    );
    const minRaw =
      earliest.rows[0]?.min_date || camp.created_at || startOfDay(now);
    const minDate = new Date(minRaw);
    start = startOfDay(minDate);
    end = startOfDay(now);
    end.setDate(end.getDate() + 1);
  } else if (preset === \"custom\") {
    const s = parseDate(req.query.start_date) || now;
    const e = parseDate(req.query.end_date) || s;
    start = startOfDay(s);
    end = startOfDay(e);
    end.setDate(end.getDate() + 1);
  } else {
    start = startOfDay(now);
    end = new Date(start);
    end.setDate(start.getDate() + 1);
    bucketType = \"hour\";
  }

  if (!end || end <= start) {
    end = new Date(start);
    end.setDate(start.getDate() + 1);
  }
  const rangeLabel = rangeLabelText(start, end);

  const diffMs = end.getTime() - start.getTime();
  const prevStart = new Date(start.getTime() - diffMs);
  const prevEnd = new Date(end.getTime() - diffMs);

  const stats = await db.query(
    `
        SELECT date_trunc($4::text, created_at) as bucket, 
               COUNT(*) FILTER (WHERE action = 'redirect') as redirects,
               COUNT(*) FILTER (WHERE action LIKE 'safe_page%') as safe
        FROM traffic_logs 
        WHERE campaign_id = $1 
          AND created_at >= $2
          AND created_at < $3
        GROUP BY bucket 
        ORDER BY bucket ASC
      `,
    [campId, start, end, bucketType]
  );

  const totals = await db.query(
    `
        SELECT COUNT(*) FILTER (WHERE action = 'redirect') as redirects,
               COUNT(*) FILTER (WHERE action LIKE 'safe_page%') as safe,
               COUNT(*) as total
        FROM traffic_logs 
        WHERE campaign_id = $1 
          AND created_at >= $2
          AND created_at < $3
      `,
    [campId, start, end]
  );

  const prevTotals = await db.query(
    `
        SELECT COUNT(*) FILTER (WHERE action = 'redirect') as redirects,
               COUNT(*) FILTER (WHERE action LIKE 'safe_page%') as safe,
               COUNT(*) as total
        FROM traffic_logs 
        WHERE campaign_id = $1 
          AND created_at >= $2
          AND created_at < $3
      `,
    [campId, prevStart, prevEnd]
  );

  const countryStats = await db.query(
    `
        SELECT country, 
               COUNT(*) FILTER (WHERE action='redirect') as redirects, 
               COUNT(*) as hits
        FROM traffic_logs 
        WHERE campaign_id=$1 
          AND created_at >= $2 
          AND created_at < $3
        GROUP BY country 
        ORDER BY hits DESC 
        LIMIT 10
    `,
    [campId, start, end]
  );

  const logs = await db.query(
    `SELECT * FROM traffic_logs WHERE campaign_id=$1 AND created_at >= $2 AND created_at < $3 ORDER BY id DESC LIMIT 50`,
    [campId, start, end]
  );

  const summary = totals.rows[0] || { redirects: 0, safe: 0, total: 0 };
  summary.redirects = Number(summary.redirects || 0);
  summary.safe = Number(summary.safe || 0);
  summary.total = Number(summary.total || 0);
  summary.fail = summary.safe;
  summary.pass_rate =
    summary.total > 0
      ? Math.round((summary.redirects / summary.total) * 1000) / 10
      : 0;

  const previous = prevTotals.rows[0] || { redirects: 0, safe: 0, total: 0 };
  previous.redirects = Number(previous.redirects || 0);
  previous.safe = Number(previous.safe || 0);
  previous.total = Number(previous.total || 0);
  previous.pass_rate =
    previous.total > 0
      ? Math.round((previous.redirects / previous.total) * 1000) / 10
      : 0;

  const delta = {
    redirects: summary.redirects - previous.redirects,
    safe: summary.safe - previous.safe,
    pass_rate: summary.pass_rate - previous.pass_rate,
  };
  const growth = {
    redirects:
      previous.redirects > 0
        ? Math.round((delta.redirects / previous.redirects) * 1000) / 10
        : null,
    safe:
      previous.safe > 0
        ? Math.round((delta.safe / previous.safe) * 1000) / 10
        : null,
    pass_rate:
      previous.pass_rate !== null
        ? Math.round(delta.pass_rate * 10) / 10
        : null,
  };

  res.render(\"admin/report_v2\", {
    user: req.session.user,
    camp,
    stats: stats.rows,
    logs: logs.rows.map(parseLogMeta),
    summary,
    previous,
    delta,
    growth,
    countryStats: countryStats.rows,
    preset,
    presetLabel: presetLabels[preset] || \"Tùy chọn\",
    bucketType,
    rangeLabel,
    start,
    end,
  });
});
"""
path.write_text(text[:start] + new_block + text[end:], encoding="utf-8")
