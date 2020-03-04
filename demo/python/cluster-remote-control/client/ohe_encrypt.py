from subprocess import call
import argparse
import csv
import pandas as pd

TEMPFILE_NAME = 'tempohe1405.csv'

def ohe(input_path, column_names=None, column_indices=None):
    """always assumes that the input .csv has a header
    output, temp .csv never has a header"""
    df = pd.read_csv(input_path)
    df.drop(columns=['CUST_REF'], inplace=True)
    if not column_names:
        mappings = dict(enumerate(df.columns))
        column_names = [mappings[i] for i in column_indices]
    df_processed = pd.get_dummies(df, prefix_sep="_", columns=column_names)
    df_processed.to_csv(TEMPFILE_NAME, index=False, header=False)


if __name__ == '__main__':

    call('make', shell=True)

    parser = argparse.ArgumentParser()
    parser.add_argument('--input_path', help='path to the input .csv')
    parser.add_argument('--output_path', help='path to the folder the final encrypted file should be saved at')
    parser.add_argument('--column_names', nargs='*', help='column namesof categorical variables', required=False)
    parser.add_argument('--column_indices', nargs='*', help='column indices of categorical variables',  required=False)


    args = parser.parse_args()
    if args.column_names and args.column_indices:
        print('Warning: both categorical names and categorical indices are specified, defaulting to names')
    if args.column_names:
        ohe(args.input_path, column_names=args.column_names)
    elif args.column_indices:
        ohe(args.input_path, column_indices=args.column_indices)
    else:
        df = pd.read_csv(args.input_path)
        df.to_csv(TEMPFILE_NAME, header=False, index=False)

    call('./encrypt-file ' + TEMPFILE_NAME + ' ' + args.output_path + " key.txt", shell=True)


