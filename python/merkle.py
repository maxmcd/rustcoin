def merkle(items):
    print(items)
    out = []
    while items:
        pair = []
        for _ in range(2):
            pair.append(items.pop(0) if items else pair[0])
        # "hashing"
        out.append(pair[0] + pair[1])
    if len(out) == 1:
        return out
    else:
        return merkle(out)


items = [1, 2, 3, 4, 5, 5, 6, 2, 6, 2, 1, 2]
print(merkle(items))