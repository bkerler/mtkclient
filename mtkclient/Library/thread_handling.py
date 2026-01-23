from queue import Queue
def writedata(filename, rq: Queue):
    """
    Optimized writer: uses buffered I/O and larger writes
    """
    try:
        with open(filename, "wb", buffering=8*1024*1024) as wf:  # 8MB buffer
            while True:
                block = rq.get(timeout=300)
                if block is None:
                    break
                try:
                    wf.write(block)
                except Exception as e:
                    print(f"Write error: {e}")
                    break
    except Exception as e:
        print(f"Writer thread exception: {e}")
    finally:
        rq.task_done()  # ensure queue doesn't hang
