import re

first = True
# hits = []
# totals = []
program_coverages = []
pc = {}
def print_pc(pc):
    hits = []
    totals = []
    for fn, ht in pc.items():
        hits.append(ht[0])
        totals.append(ht[1])
        # print(fn)
    if sum(totals) == 0:
        print("No coverage")
    else:
        print(sum(hits) / sum(totals))
with open("fuzz_all_llm4.log") as f:
    for line in f:
        if line.startswith("Running fuzzer"):# and line.endswith("..."):
            if not first:
                # print_pc(pc)
                # hits = []
                # totals = []
                program_coverages.append((program, pc))
                pc = {}
            # print(line, end="")
            program = re.match(r"Running fuzzer (.*)...", line).group(1)
            first = False
            # print(program)
        if line.startswith("COVERED_FUNC:"):
            m = re.search(r"edges: ([0-9]+)/([0-9]+)", line)
            hit, total = m.groups()
            # hits.append(int(hit))
            # totals.append(int(total))
            function = line.split()[5]
            pc[function] = (int(hit), int(total))
        if line.startswith("UNCOVERED_FUNC:"):
            m = re.search(r"edges: ([0-9]+)/([0-9]+)", line)
            hit, total = m.groups()
            # hits.append(int(hit))
            # totals.append(int(total))
            function = line.split()[5]
            pc[function] = (int(hit), int(total))
    if not first:
        # print_pc(pc)
        program_coverages.append((program, pc))
        # print(sum(hits) / sum(totals))

for program, pc in program_coverages:
    print(program)
    print_pc(pc)
