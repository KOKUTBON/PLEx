def process_file_lines(path):
    # Safe: open file once outside loop
    results = []
    with open(path) as fh:
        for line in fh:
            results.append(line.strip())
    return results
