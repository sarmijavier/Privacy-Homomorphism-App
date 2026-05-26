import csv
import json
from domingo_ferrer_2002 import decrypt


# -- deserialize ---------------------------------------------------------------

def str_to_ct(s: str) -> dict:
    return {int(j): int(cj) for j, cj in json.loads(s)}

def dict_to_key(d: dict) -> dict:
    return {
        "m":          int(d["m"]),
        "d":          int(d["d"]),
        "r":          int(d["r"]),
        "m_prime":    int(d["m_prime"]),
        "r_inv":      int(d["r_inv"]),
        "r_pows":     [int(x) for x in d["r_pows"]],
        "r_inv_pows": [int(x) for x in d["r_inv_pows"]],
        "s":          float(d["s"]),
    }


# -- main ----------------------------------------------------------------------

def decrypt_and_compute_all(
    results_path:  str = "encrypted_results.json",
    key_path:      str = "key.json",
    meta_path:     str = "metadata.json",
    out_means_csv: str = "means.csv",
    out_regr_csv:  str = "regression.csv",
) -> None:

    # 1. Load resources
    with open(key_path, encoding='utf-8') as f:
        key = dict_to_key(json.load(f))

    with open(meta_path, encoding='utf-8') as f:
        meta = json.load(f)

    with open(results_path, encoding='utf-8') as f:
        results = json.load(f)

    n_rows         = meta["n_rows"]
    columns        = meta["columns"]
    decimal_places = meta["decimal_places"]

    # 2. Decrypt means for all columns
    raw_decrypted_sums = {}
    means = {}

    for col in columns:
        dp    = int(decimal_places[col])
        scale = 10 ** dp

        c_sum_str = results["column_sums"][col]
        dec_sum   = decrypt(str_to_ct(c_sum_str), key)

        raw_decrypted_sums[col] = dec_sum
        means[col] = dec_sum / (n_rows * scale)

    # Save the FIRST CSV (means.csv)
    with open(out_means_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerow({col: f"{v:.10g}" for col, v in means.items()})

    print(f"[step3] Saved first file: {out_means_csv}")

    # 3. Decrypt and compute regression stats
    reg_data = results["regression_stats"]
    col_x    = reg_data["col_x"]
    col_y    = reg_data["col_y"]

    scale_x = 10 ** int(decimal_places[col_x])
    scale_y = 10 ** int(decimal_places[col_y])

    dec_x  = raw_decrypted_sums[col_x]
    dec_y  = raw_decrypted_sums[col_y]
    dec_xy = decrypt(str_to_ct(reg_data["sum_xy"]), key)
    dec_x2 = decrypt(str_to_ct(reg_data["sum_x2"]), key)

    numerator   = (n_rows * dec_xy) - (dec_x * dec_y)
    denominator = (n_rows * dec_x2) - (dec_x * dec_x)

    covariance = numerator / ((n_rows ** 2) * scale_x * scale_y)

    if denominator == 0:
        beta1 = float('inf')
    else:
        beta1 = (numerator / denominator) * (scale_x / scale_y)

    # Save the SECOND CSV (regression.csv)
    with open(out_regr_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        # Write headers
        writer.writerow(["Covariance", "Beta1_Slope"])
        # Write data
        writer.writerow([f"{covariance:.6f}", f"{beta1:.6f}"])

    print(f"[step3] Saved second file: {out_regr_csv}")


if __name__ == "__main__":
    
    decrypt_and_compute_all(
        results_path="outputs/encrypted_results.json",
        key_path="diabetes_key.json",
        meta_path="metadata.json",
        out_means_csv="means.csv",
        out_regr_csv="regression.csv"
    )