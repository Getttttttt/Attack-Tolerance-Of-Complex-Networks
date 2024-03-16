import os
import pandas as pd

# 定义函数合并fc_values.csv文件
def merge_csv_files(sorted_directories):
    # 初始化一个空的DataFrame用于存放最终结果
    merged_df = pd.DataFrame()
    
    for directory in sorted_directories:
        # 构造文件路径
        file_path = os.path.join(directory, 'fc_values.csv')
        
        # 读取csv文件
        df = pd.read_csv(file_path)
        
        # 如果merged_df为空，则直接赋值
        if merged_df.empty:
            merged_df = df.set_index(df.columns[0])
            # 重命名列名为文件夹名
            merged_df.rename(columns={merged_df.columns[0]: directory}, inplace=True)
        else:
            # 如果merged_df不为空，则按照变量名合并
            temp_df = df.set_index(df.columns[0])
            merged_df = merged_df.join(temp_df.rename(columns={temp_df.columns[0]: directory}), how='outer')
    
    return merged_df

# 获取当前路径
current_path = '.'

# 获取所有文件夹
directories = [os.path.join(current_path, d) for d in os.listdir(current_path) if os.path.isdir(d)]

# 筛选出以"Undirected"结尾的文件夹
undirected_folders = [d for d in directories if d.endswith('Undirected')]

# 根据文件夹名字前的内容进行排序
sorted_directories = sorted(undirected_folders, key=lambda x: x.split('Undirected')[0])

# 合并csv文件
merged_df = merge_csv_files(sorted_directories)

# 输出到FinalResult.csv文件中
merged_df.to_csv('FinalResult.csv')
