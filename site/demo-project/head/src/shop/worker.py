import time


async def poll(queue):
    while True:
        item = await queue.get()
        time.sleep(0.5)
        print(item)


def first_token(header):
    return header.split(",")[0]


def stats(counts):
    if len(counts) > 0:
        total = sum([c for c in counts])
        return total
    return 0
