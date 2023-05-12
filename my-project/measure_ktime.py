total = 0
num = 0

with open("/home/alex/out5.txt", "r") as f:
    for l in f.readlines():
        if "_hot_path" in l:
            t = l.split("_hot_path': ")[1]
            t2 = int(t.split(" ns")[0])
            total += t2
            num += 1

    print("Avg ns:", total / num)
    print("Times ran:", num)