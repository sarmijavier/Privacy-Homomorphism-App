import csv
import json
import argparse
from domingo_ferrer_2002 import homo_add, homo_mul

# Serialize functions
def str_to_ct(s: str) -> dict:
    return {int(j): int(cj) for j, cj in json.loads(s)}

def ct_to_str(ct: dict) -> str:
    return json.dumps([[str(j), str(cj)] for j, cj in sorted(ct.items())],
                      separators=(',', ':'))

def server_stats(
    enc_path:  str = "encrypted_data.csv",
    meta_path: str = "metadata.json",
    out_csv_path:  str = "encrypted_results.csv",
    out_json_path: str = "encrypted_results.json"
) -> None:

    # Read metadata to get m
    with open(meta_path, encoding='utf-8') as f:
        meta = json.load(f)

    m       = int(meta["m"])
    columns = meta["columns"]
    n_rows  = meta["n_rows"]

    # Define independent (X) and dependent (Y) variables
    col_x = "Age"
    col_y = "Glucose"

    print(f"[step2] Computing regression stats for X={col_x}, Y={col_y}")
    print(f"[step2] Params: n={n_rows} rows, |m|={len(str(m))} digits")
    
    # Read encrypted csv
    with open(enc_path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        rows   = list(reader)

    if len(rows) != n_rows:
        raise ValueError(f"Expected {n_rows} rows, found {len(rows)}")

    # Initialize sums for ALL columns
    col_sums = {col: str_to_ct(rows[0][col]) for col in columns}
    
    # Initialize specific products for regression
    cx_0 = col_sums[col_x]
    cy_0 = col_sums[col_y]
    sum_xy = homo_mul(cx_0, cy_0, m)
    sum_x2 = homo_mul(cx_0, cx_0, m)

    # Accumulate homomorphic sums
    print(f"[step2] Aggregating {n_rows} rows...")
    for i, row in enumerate(rows[1:], start=2):
        
        # Add to general column sums
        for col in columns:
            c_val = str_to_ct(row[col])
            col_sums[col] = homo_add(col_sums[col], c_val, m)
            
        # Add to regression products
        cx = str_to_ct(row[col_x])
        cy = str_to_ct(row[col_y])
        sum_xy = homo_add(sum_xy, homo_mul(cx, cy, m), m)
        sum_x2 = homo_add(sum_x2, homo_mul(cx, cx, m), m)

    # 1. Generate CSV output for the web server display
    csv_row_formatted = {col: ct_to_str(c) for col, c in col_sums.items()}
    csv_row_formatted["sum_xy"] = ct_to_str(sum_xy)
    csv_row_formatted["sum_x2"] = ct_to_str(sum_x2)

    extended_columns = columns + ["sum_xy", "sum_x2"]

    with open(out_csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=extended_columns)
        writer.writeheader()
        writer.writerow(csv_row_formatted)

    # 2. Generate JSON output for step 3
    results_json = {
        "column_sums": {col: ct_to_str(c) for col, c in col_sums.items()},
        "regression_stats": {
            "col_x": col_x,
            "col_y": col_y,
            "sum_xy": ct_to_str(sum_xy),
            "sum_x2": ct_to_str(sum_x2)
        }
    }

    with open(out_json_path, 'w', encoding='utf-8') as f:
        json.dump(results_json, f, indent=4)

if __name__ == "__main__":
    server_stats()