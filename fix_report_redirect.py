from pathlib import Path
path = Path('src/server-admin.js')
text = path.read_text(encoding='utf-8')
start = text.find('app.get("/campaigns/:id/report",')
end = text.find('app.get("/campaigns/:id/logs"', start)
if start == -1 or end == -1:
    raise SystemExit('route markers not found')
new_block = """app.get(\"/campaigns/:id/report\", checkAuth, async (req, res) => {
  const campId = req.params.id;
  const query = req.originalUrl.includes("?")
    ? req.originalUrl.slice(req.originalUrl.indexOf("?"))
    : "";
  return res.redirect(`/campaigns/${campId}/report/v2${query}`);
});

"""
text = text[:start] + new_block + text[end:]
path.write_text(text, encoding='utf-8')
