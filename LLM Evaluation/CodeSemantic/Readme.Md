# CodeSemantic

CodeSemantic is a framework for evaluating code understanding through semantic reasoning tasks.

## 📂 Repository Structure

- **Main Script**  
  The entry point for running experiments:  
  `CodeSemantic/statement_semantic.py`

- **Run Scripts**  
  To reproduce our results, use the bash scripts in:  
  `CodeSemantic/Run/`

- **Results**  
  - Task-wise accuracy results are saved in:  
    `CodeSemantic/"task"_accuracy_results/`
  - Detailed results are saved in:  
    `CodeSemantic/Detailed_Results/`

- **Prompting Templates**  
  Templates for various prompting tasks are located at:  
  `CodeSemantic/src/pt/statement_pt/`

- **Dataset**  
  All datasets used for training and evaluation are stored in:  
  `CodeSemantic/dataset/`

- **Dataset Mapping Utility**  
  The script that maps dataset entries to their corresponding `data_id`:  
  `CodeSemantic/utils.py`

## 🚀 How to Reproduce Results

1. Activate your environment and install the requirements.

2. Run any task-specific script from the `Run` folder. For example:
    ```bash
    bash CodeSemantic/Run/run_RQ1.sh
    ```

3. Check the results in:
    - `CodeSemantic/"task"_accuracy_results/`
    - `CodeSemantic/Detailed_Results/`
