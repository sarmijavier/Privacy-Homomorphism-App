import pandas as pd
import numpy as np

def verify_results(raw_csv_path, means_csv_path, regr_csv_path):
    # Load original unencrypted data
    df = pd.read_csv(raw_csv_path)
    numeric_df = df.apply(pd.to_numeric, errors="coerce")

    # Calculate local means
    local_means = numeric_df.mean()

    # Define variables for regression
    col_x = "Age"
    col_y = "Glucose"

    # Calculate local covariance and beta1
    # We use ddof=0 to calculate population variance/covariance
    # because the homomorphic step divides by N, not N-1
    cov_matrix = numeric_df[[col_x, col_y]].cov(ddof=0)
    local_cov = cov_matrix.loc[col_x, col_y]
    
    local_var_x = numeric_df[col_x].var(ddof=0)
    local_beta1 = local_cov / local_var_x

    # Load decrypted results from Step 3
    enc_means_df = pd.read_csv(means_csv_path)
    enc_regr_df = pd.read_csv(regr_csv_path)

    print("=== Comparing Means ===")
    for col in numeric_df.columns:
        local_val = local_means[col]
        enc_val = enc_means_df[col].iloc[0]

        # Compare using numpy.isclose due to floating point inaccuracies
        is_match = np.isclose(local_val, enc_val, rtol=1e-5)
        match_status = "OK" if is_match else "FAIL"
        print(f"{col:<20} | Local: {local_val:.6f} | Decrypted: {enc_val:.6f} | {match_status}")

    print("\n=== Comparing Regression Stats ===")
    enc_cov = enc_regr_df["Covariance"].iloc[0]
    enc_beta1 = enc_regr_df["Beta1_Slope"].iloc[0]

    cov_match = "OK" if np.isclose(local_cov, enc_cov, rtol=1e-5) else "FAIL"
    beta1_match = "OK" if np.isclose(local_beta1, enc_beta1, rtol=1e-5) else "FAIL"

    print(f"Covariance | Local: {local_cov:.6f} | Decrypted: {enc_cov:.6f} | {cov_match}")
    print(f"Beta1      | Local: {local_beta1:.6f} | Decrypted: {enc_beta1:.6f} | {beta1_match}")


if __name__ == "__main__":
    # Define paths to your specific files
    raw_csv = r"diabetes.csv"  
    means_csv = r"means.csv"
    regr_csv = r"regression.csv"
    
    verify_results(raw_csv, means_csv, regr_csv)