ids = request.args.get("ids", "")
try:
    id_list = [int(x) for x in ids.split(",") if x.strip()]
except ValueError:
    abort(400, "Invalid id list")

if not id_list:
    return []

MAX_IDS = 100
id_list = id_list[:MAX_IDS]

placeholders = ",".join(["%s"] * len(id_list))
q = f"SELECT * FROM users WHERE id IN ({placeholders})"
cursor.execute(q, tuple(id_list))
