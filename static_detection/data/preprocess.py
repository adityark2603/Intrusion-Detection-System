import pandas as pd

# load Zeek-extracted data
df = pd.read_csv("flows_raw.tsv", sep="\t", header=None)

# assign column names (VERY IMPORTANT)
df.columns = ["duration", "orig_bytes", "resp_bytes", "proto"]

# force numeric columns
for col in ["duration", "orig_bytes", "resp_bytes"]:
    df[col] = pd.to_numeric(df[col], errors="coerce")

# encode protocol (tcp/udp → numbers)
df["proto"] = df["proto"].astype("category").cat.codes

# replace NaN with 0
df = df.fillna(0)

# save ML-ready file
df.to_csv("flows_ready.csv", index=False)

print(df.head())
print(df.dtypes)

