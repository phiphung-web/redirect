from pathlib import Path
path = Path('src/server-admin.js')
text = path.read_text(encoding='utf-8')
start = text.find('const presetLabels = {')
if start == -1:
    raise SystemExit('start not found')
end = text.find('};', start)
if end == -1:
    raise SystemExit('end not found')
end = end + 2
new_block = '''const presetLabels = {
    today: "Hôm nay",
    this_week: "Tuần này",
    this_month: "Tháng này",
    this_year: "Năm nay",
    all: "Tất cả",
    custom: "Tùy chọn",
  };
'''
text = text[:start] + new_block + text[end:]
path.write_text(text, encoding='utf-8')
