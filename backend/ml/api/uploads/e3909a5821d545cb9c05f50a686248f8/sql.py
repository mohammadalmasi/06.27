ids = request.args.get("ids", "")
id_list = [int(x) for x in ids.split(",") if x.strip() != ""]
placeholders = ",".join(["%s"] * len(id_list))

q = "SELECT * FROM users WHERE id IN (" + placeholders + ")"
cursor.execute(q, tuple(id_list))
