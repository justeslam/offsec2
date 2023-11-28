# Function to clean data
def process_data(file_name):
    if not os.path.exists(file_name):
        logging.error(f"The file {file_name} does not exist.")
        exit()

    # Load the CSV file
    try:
        df = pd.read_csv(file_name)
    except Exception as e:
        logging.error(f"An error occurred while loading the Excel file: {e}")
        exit()

    # Remove duplicates in csv raw data
    df = df.drop_duplicates()

    # Iterate over the columns
    for col in df.columns:
        try:
            if df[col].name != "Case Number":
            # Check if the column can be converted to numeric
                temp_col = df.fillna(0, inplace=True)
                temp_col = pd.to_numeric(df[col].replace(',', '', regex=True), errors='coerce')
                # df[col] = temp_col
                if temp_col.notna().all():
                #     # If it can, convert the column to numeric
                    df[col] = temp_col
        except Exception as e:
            # If it can't, it's (likely) a text column
            df[col].replace(0, "Unknown")
            # Strip whitespace
            df[col] = df[col].str.strip()
            # Convert to lowercase
            df[col] = df[col].str.lower()
            continue

    # Convert integer columns to float
    for col in df.select_dtypes(include='int64').columns:
        df[col] = df[col].astype(float)

    # Convert currency columns to float
    for col in df.columns:
        if df[col].dtype == 'object':
            try:
                df[col] = df[col].replace('[\$,]', '', regex=True).astype(float)
            except Exception as e:
                print(f"{col}': {e}")
                continue

    # Save the cleaned data back to the same Excel file in a new sheet
    try:
        df.to_csv('Cleaned Data.csv', index=False)
        return df
    except Exception as e:
        print(f"An error occurred while saving the file: {e}")
        return

    print("Data cleaning completed successfully.")
