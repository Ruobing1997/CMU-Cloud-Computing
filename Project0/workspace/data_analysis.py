#!/usr/bin/env python
# coding: utf-8

# In[1]:


import pandas as pd
import sys
import argparse


# In[18]:


def load_data_to_series(input_file):
    """
    Load the input file into a Series.
    Please read the documentation of the method `pandas.read_csv`:
    https://pandas.pydata.org/pandas-docs/stable/generated/pandas.read_csv.html?highlight=index_col

    The default behavior of read_csv will infer the column names using the first line of the input file.
    In the provided Wikipedia dataset, the first line of the input file is not the column names; 
    hence, you need to change this default behavior.
    
    Hint: 
    1. How to read a TSV file using the read_csv method by specifying the delimiter
    2. How to not infer the first line as the column names
    3. How to read the data into a Series instead of a Dataframe
    4. How to specify the column to be used as the row labels
    
    :param input_file: the path to the input file
    :return: the Series
    """
    
    # TODO: Load the input_file in to a Series
    # raise NotImplementedError("To be implemented")
    series = pd.read_csv(input_file,sep='\t', header = None, index_col = 0).squeeze("columns")

    
    return series


# In[19]:


def q6():
    """
    Print a small sample of a Series as CSV
    
    To view the top n records, read the documentation:
    https://pandas.pydata.org/pandas-docs/stable/basics.html#head-and-tail
    
    output format:
    <page title>,<page view>
    <page title>,<page view>
    <page title>,<page view>
    ...
    
    """
    
    # read the output into series
    series = load_data_to_series("output")
    
    # TODO: replace "None" with your implementation to select the first 10 records
    # raise NotImplementedError("To be implemented")
    res = series.head(10)
    
    # print the result to standard output in the CSV format
    res.to_csv(sys.stdout, header=None)


# In[5]:


def q7():
    """
    Get values by index label
    
    Since the page title is the label of the Series, you can get the page view by page title.
    Please read the documentation:
    https://pandas.pydata.org/pandas-docs/stable/dsintro.html#series-is-dict-like
    
    output format:
    <page view>
    """
    
    # read the output into a Series 
    series = load_data_to_series("output")
    
    # TODO: replace "None" with your implementation to select the row with the title "Cloud_computing"
    # raise NotImplementedError("To be implemented")
    res = series["Cloud_computing"]
    
    # print the result to standard output
    print(res)


# In[7]:


def q8():
    """
    Generates descriptive statistics of a Series
    
    Please read the documentation of the Series and find the method to show all the descriptive statistics.
    https://pandas.pydata.org/pandas-docs/stable/generated/pandas.Series.html?highlight=descriptive
    
    output format:
    
    count,<number>
    mean,<number>
    std,<number>
    min,<number>
    25%,<number>
    50%,<number>
    75%,<number>
    max,<number>
    
    """
    
    # read the output into a Series
    series = load_data_to_series("output")
    
    # TODO: generate the descriptive statistics (replace "None" with your implementation)
    # raise NotImplementedError("To be implemented")
    res = series.describe()
    
    # print the result to standard output in csv format
    res.to_csv(sys.stdout, encoding='utf-8', header=None)


# In[9]:


def q9():
    """
    Data filtering in Series
    
    Boolean indexing can be used to filtering data in a Series.
    https://pandas.pydata.org/pandas-docs/stable/indexing.html#boolean-indexing
    
    output format:
    <page title>,<page view>
    <page title>,<page view>
    <page title>,<page view>
    ...
    
    """
    
    # read the output into a Series
    series = load_data_to_series("output")
    
    # TODO: replace "None" with your implementation to
    #       select the row with view_count greater or equal to 2000 and less than 3000 
    #       i.e., [2000, 3000)
    # raise NotImplementedError("To be implemented")
    res = series[(series >= 2000) & (series < 3000)]
    # print the result to standard output in the CSV format
    res.to_csv(sys.stdout, encoding='utf-8', header=None)


# In[11]:


def main():
    parser = argparse.ArgumentParser(
    description="Data Analysis")
    parser.add_argument("-r",
                        metavar='<question_id>',
                        required=False)
    args = parser.parse_args()
    question = args.r

    if question is None:
        q6()
        q7()
        q8()
        q9()
    elif question == "q6":
        q6()
    elif question == "q7":
        q7()
    elif question == "q8":
        q8()
    elif question == "q9":
        q9()
    else:
        print("Invalid question")
        
if __name__ == "__main__":
    main()

