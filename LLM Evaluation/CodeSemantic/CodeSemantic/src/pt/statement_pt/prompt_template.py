PROMPT_REGISTRY = {
    "pt0": {
        "statement_msg": (
            "You will be given {lang} code snippets with different types of statements "
            "(assignment, branch, or function calls). For each, you'll see:\n"
            "1. The complete code snippet\n"
            "2. A highlighted statement\n"
            "3. Variable values before that statement executes\n\n"
            "Your task is to predict the value after the statement executes.\n\n"
            "Here are {shot} worked examples:\n\n"
            "----------------------------------------\n"
        ),
        "block_msg": (
            "You will be given {lang} code blocks with specific statements highlighted. "
            "For each, you'll see:\n"
            "1. The complete code block\n"
            "2. A highlighted statement\n"
            "3. The code block input\n\n"
            "Your task is to predict the value after executing the highlighted statement based on the given code block input.\n\n"
            "Here are {shot} worked examples:\n\n"
            "----------------------------------------\n"
        ),
        "loop_msg": (
            "You will be given {lang} code snippets containing loops with:\n"
            "1. The complete loop structure\n"
            "2. Specific input values\n"
            "3. Questions about loop behavior\n\n"
            "Your task is to analyze the loop's execution or value of a variable after loop's execution based on the given inputs.\n\n"
            "Here are {shot} worked examples:\n\n"
            "----------------------------------------\n"
        ),
        "input_output_msg": (
            "You will be given {lang} code snippets with:\n"
            "1. Complete function implementations\n"
            "2. Either input or output values specified\n\n"
            "Your task is to:\n"
            "- Predict outputs when given inputs\n"
            "- Determine inputs when given outputs\n\n"
            "Here are {shot} worked examples:\n\n"
            "----------------------------------------\n"
        ),
        "assignment": (
            "Given the following {lang} code snippet and the selected statement, "
            "the local variable values before the statements are shown as follows, "
            "what will be the value of the selected statement after executing the selected statement?\n\n"
            "Code Snippet\n"
            "```{lang}\n"
            "{code}\n"
            "```\n\n"
            "Selected Statement: {statement}\n\n"
            "Local Variables:\n"
            "{variables}\n\n"
            "Please put your answer in the <ans></ans> tags, Do not include any extra information."
        ),
        "branch": (
            "Given the following {lang} code snippet and the selected branch statement, "
            "the local variable values before the branch statements are shown as follows, "
            "Will the nvidbranch be executed based on the condition expression variable values? Please answer \"Yes\" or \"No\".\n\n"
            "Code Snippet\n"
            "```{lang}\n"
            "{code}\n"
            "```\n\n"
            "Selected Branch Statement: {statement}\n\n"
            "If Expression Variables:\n"
            "{variables}\n\n"
            "Please put your answer in the <ans></ans> tags, Do not include any extra information."
        ),
        "conditional": (
            "Given the following {lang} code snippet and the selected branch statement, "
            "the local variable values before the branch statements are shown as follows, "
            "Will the nvidbranch be executed based on the condition expression variable values? Please answer \"Yes\" or \"No\".\n\n"
            "Code Snippet\n"
            "```{lang}\n"
            "{code}\n"
            "```\n\n"
            "Question: {question}\n\n"
            "Please put your answer in the <ans></ans> tags, Do not include any extra information."
        ),
        "api": (
            "Given the following {lang} code snippet and the selected statement, "
            "the local variable values of the api/function parameters are shown as follows, "
            "what will be the value after the selected API/Function call?\n\n"
            "Code Snippet\n"
            "```{lang}\n"
            "{code}\n"
            "```\n\n"
            "Selected API/Function: {statement}\n\n"
            "API/Function Parameters:\n"
            "{variables}\n\n"
            "Please put your answer in the <ans></ans> tags, Do not include any extra information."
        ),
        "block": (
            "Given the following {lang} code snippet and the selected statement, "
            "the input of the code snippet is given as follows, "
            "what will be the value after executing the selected statement?\n\n"
            "Code Snippet\n"
            "```{lang}\n"
            "{code}\n"
            "```\n\n"
            "Selected Statement: {statement}\n\n"
            "Function Inputs:\n"
            "{inputs}\n\n"
            "Please put your answer in the <ans></ans> tags"
        ),
        "output": (
            "Given the following {lang} code snippet and input of the code, "
            "what will be the output of the code given the input value?\n\n"
            "Code Snippet\n"
            "```{lang}\n"
            "{code}\n"
            "```\n\n"
            "Function Inputs:\n"
            "{input}\n\n"
            "Please put your answer in the <ans></ans> tags"
        ),
        "input": (
            "Given the following {lang} code snippet and output of the code, "
            "what will be the input of the code given the output value?\n\n"
            "Code Snippet\n"
            "```{lang}\n"
            "{code}\n"
            "```\n\n"
            "Function Output:\n"
            "{output}\n\n"
            "Please put your answer in the <ans></ans> tags"
        ),
        "loop_iteration": (
            "Given the following {lang} code snippet with function call showing the input of the code,\n\n"
            "Code Snippet\n"
            "```{lang}\n"
            "{code}\n"
            "```\n\n"
            "Question:\n"
            "{question}\n\n"
            "Please put your answer in the <ans></ans> tags"
        ),
        "loop_body": (
            "Given the following {lang} code snippet with function call showing the input of the code,\n\n"
            "Code Snippet\n"
            "```{lang}\n"
            "{code}\n"
            "```\n\n"
            "Question:\n"
            "{question}\n\n"
            "Please put your answer in the <ans></ans> tags"
        ),
        "alias": (
            "Given the following {lang} code snippet and its input parameters:\n\n"
            "You are given two pointer variables in the code:\n"
            "- Pointer A: {pointer_1}\n"
            "- Pointer B: {pointer_2}\n\n"
            "Determine if these pointers are aliases (reference the same memory address).\n"
            "Respond with:\n"
            "- \"Yes\" if they point to the same memory location\n"
            "- \"No\" if they point to different locations\n\n"
            "Code:\n"
            "```{lang}\n"
            "{code}\n"
            "```\n\n"
            "Function Input:\n"
            "{input}\n\n"
            "Question:\n"
            "Do {pointer_1} and {pointer_2} in (line {line_1}) alias the same memory address?\n\n"
            "Provide your answer within <ans></ans> tags."
        ),
        "assignment_cot": (
            "1. Examine the assignment statement: '{statement}'\n"
            "2. Current variable values: {variables}\n"
            "3. Evaluate the right-hand side expression using these values\n"
            "4. The result becomes the new value of the left-hand side variable"
        ),
        "branch_cot": (
            "1. Examine the branch condition: '{statement}'\n"
            "2. Current variable values: {variables}\n"
            "3. Evaluate the conditional expression using these values\n"
            "4. Determine if the condition is true or false\n"
            "5. This determines whether the branch will be taken"
        ),
        "api_cot": (
            "1. Examine the API call: '{statement}'\n"
            "2. Current parameter values: {variables}\n"
            "3. Determine what this API/function does with these parameters\n"
            "4. Compute or predict the return value based on the function's logic"
        ),
        "block_cot": (
            "1. Identify the highlighted statement {statement} in the code block\n"
            "2. Examine the given inputs {input} and how they flow into the code\n"
            "3. Trace the execution up to the highlighted statement\n"
            "4. Determine the value produced by the highlighted statement\n"
            "5. Verify the value based on the code logic and inputs"
        ),
        "loop_iteration_cot": (
            "1. Initialize loop variables with starting values\n"
            "2. Check the loop condition\n"
            "3. Execute the loop body if condition is true\n"
            "4. Update loop variables\n"
            "5. Repeat until condition becomes false"
        ),
        "loop_body_cot": (
            "1. Identify all variables used in the loop body\n"
            "2. Check their values at current iteration\n"
            "3. Execute each operation in sequence\n"
            "4. Track how variables change during this iteration"
        ),
        "post_loop_analysis_cot": (  
            "1. Identify the loop's exit condition (why it terminated)\n"  
            "2. Check the final values of all modified loop variables\n"  
            "3. Verify the last valid iteration before termination\n"  
            "4. Check if loop was never entered (initial condition false)\n"  
            "5. Trace the target variable's evolution through all iterations\n"  
            "6. Account for breaks/continues or external side effects"  
        ),
        "output_cot": (
            "1. Identify all input variables of {input} and their given values\n"
            "2. Trace the execution path through the function step by step\n"
            "3. For each operation:\n"
            "   a. Identify which variables are involved\n"
            "   b. Apply the operation to current values\n"
            "   c. Update the variable states\n"
            "4. When reaching return statement/output point:\n"
            "   a. Note the final values of return variables\n"
            "   b. Format the output according to function specification\n"
            "5. Verify the output matches all transformations applied"
        ),
        "input_cot": (
            "1. Analyze the given output value {output} and its structure\n"
            "2. Work backwards through the function's operations:\n"
            "   a. Identify the last transformation applied\n"
            "   b. Determine what input would produce this output\n"
            "   c. Move to previous operation in reverse order\n"
            "3. For conditional branches:\n"
            "   a. Determine which path must have been taken\n"
            "   b. Note the necessary conditions for this path\n"
            "4. For loops:\n"
            "   a. Determine how many iterations occurred\n"
            "   b. Track how variables changed each iteration\n"
            "5. Verify the reconstructed input:\n"
            "   a. Forward-execute with proposed input\n"
            "   b. Confirm it produces the given output"
        )
    },
    "pt1": {
        "statement_msg": (
            "Here's some {lang} code. Each example highlights a single statement of (assignment, branch, or function calls) and shows you what the variable values look like just before it runs.\n"
            "Your goal? Figure out what the result will be right after that statement runs.\n\n"
            "Here are {shot} examples to walk you through it:\n\n"
            "----------------------------------------\n"
        ),
        "block_msg": (
            "Take a look at the {lang} code blocks. One statement is highlighted in each.\n"
            "You’ll also see the input values going into the function. Based on those, try to figure out what the highlighted line will do.\n\n"
            "Here are {shot} examples that show how it works:\n\n"
            "----------------------------------------\n"
        ),
        "loop_msg": (
            "Let’s explore some loops in {lang}. You’ll get the full loop structure along with the input values used in the code.\n"  
            "I’ll ask you questions about how the loop body or post-loop values behave with those inputs.\n"  
            "Here’s how it works with {shot} example(s):\n"
            "----------------------------------------\n"
        ),
        "input_output_msg": (
            "Here’s some {lang} code. You’ll either get the inputs or the outputs, but not both.\n"
            "Your task is to fill in the missing part—predict the output if you know the input, or figure out what input must’ve produced the output.\n\n"
            "Check out these {shot} examples for reference:\n\n"
            "----------------------------------------\n"
        ),
        "assignment": (
            "You’re given some {lang} code and one specific assignment line.\n"
            "Here are the local variables just before that line runs. Can you figure out what the value of the assignment will be afterward?\n\n"
            "Code Snippet:\n"
            "```{lang}\n"
            "{code}\n"
            "```\n\n"
            "Statement: {statement}\n\n"
            "Before Values:\n"
            "{variables}\n\n"
            "Answer using <ans></ans> tags, Do not include any extra information."
        ),
        "branch": (
            "Here’s a branch (if) statement in {lang}, and the values of the variables it uses.\n"
            "Will the branch run? Answer 'Yes' or 'No'.\n\n"
            "Code:\n"
            "```{lang}\n"
            "{code}\n"
            "```\n\n"
            "Branch Statement: {statement}\n\n"
            "Condition Variables:\n"
            "{variables}\n\n"
            "Answer using <ans></ans> tags, Do not include any extra information."
        ),
        "conditional": (
            "Here’s a branch (if) block statement in {lang}.\n"
            "Will the branch run given the function call? Answer 'Yes' or 'No'.\n\n"
            "Code:\n"
            "```{lang}\n"
            "{code}\n"
            "```\n\n"
            "Question: {question}\n\n"
            "Answer using <ans></ans> tags, Do not include any extra information."
        ),
        "api": (
            "Here’s a function or API call in {lang} with some parameters.\n"
            "Based on the inputs, what will it return?\n\n"
            "Code:\n"
            "```{lang}\n"
            "{code}\n"
            "```\n\n"
            "Call: {statement}\n\n"
            "Parameter Values:\n"
            "{variables}\n\n"
            "Answer using <ans></ans> tags, Do not include any extra information."
        ),
        "block": (
            "Here’s a full function in {lang} and a line of code inside it we care about.\n"
            "Given the function’s inputs, what value will that line produce?\n\n"
            "Code:\n"
            "```{lang}\n"
            "{code}\n"
            "```\n\n"
            "Statement: {statement}\n\n"
            "Inputs:\n"
            "{inputs}\n\n"
            "Answer using <ans></ans> tags"
        ),
        "output": (
            "Here’s some {lang} code and the inputs passed into it.\n"
            "What output do you expect from it?\n\n"
            "Code:\n"
            "```{lang}\n"
            "{code}\n"
            "```\n\n"
            "Inputs:\n"
            "{input}\n\n"
            "Answer using <ans></ans> tags"
        ),
        "input": (
            "You know the output of a piece of {lang} code. Can you figure out what the input must’ve been?\n\n"
            "Code:\n"
            "```{lang}\n"
            "{code}\n"
            "```\n\n"
            "Output:\n"
            "{output}\n\n"
            "Answer using <ans></ans> tags"
        ),
        "loop_iteration": (
            "Take a look at this {lang} loop with some given inputs.\n"
            "Question:\n"
            "{question}\n\n"
            "Code:\n"
            "```{lang}\n"
            "{code}\n"
            "```\n\n"
            "Answer using <ans></ans> tags"
        ),
        "loop_body": (
            "This is a {lang} loop and what the input to the function looks like.\n"
            "I’ll ask you something about what happens inside the loop body.\n\n"
            "Code:\n"
            "```{lang}\n"
            "{code}\n"
            "```\n\n"
            "Question:\n"
            "{question}\n\n"
            "Answer using <ans></ans> tags"
        ),
        "assignment_cot": (
            "Let’s figure out the result of the assignment: '{statement}'\n"
            "You’ve got the current variable values: {variables}\n"
            "Think through the right-hand side, then update the left-hand side with the result."
        ),
        "branch_cot": (
            "Here’s the condition: '{statement}'\n"
            "These are the variable values: {variables}\n"
            "Evaluate the condition. Is it true or false? That tells you if the branch runs."
        ),
        "api_cot": (
            "This is the function call: '{statement}'\n"
            "With these parameter values: {variables}\n"
            "Figure out what the function does and predict the return value."
        ),
        "block_cot": (
            "First, trace the execution flow till the highlighted statement {statement} and {input} of the given input,\n"
            "Then identify the variables associated with the statement\n"
            "Next use the trace execution flow to evaluate the statement\n"
            "What value does the statement produce?"
        ),
        "loop_iteration_cot": (
            "Start the loop using the initial values.\n"
            "Check the condition, run the body, update, and repeat.\n"
            "Keep going until the loop ends."
        ),
        "loop_body_cot": (
            "Look at the variables at the start of this iteration.\n"
            "Go through each line in the loop body.\n"
            "What happens to the variables by the end?"
        ),
        "post_loop_analysis_cot": (  
            "See why the loop stopped (condition failed).\n"  
            "Check the final values of all changed variables.\n"  
            "What did the last iteration do before ending?\n"
            "What would be the variable value after loop termination?\n"  
        ),
        "output_cot": (
            "We’re given inputs: {input}\n"
            "Walk through the code step by step.\n"
            "Watch how the values change until we get the final output.\n"
            "Check that it matches what the function should return."
        ),
        "input_cot": (
            "We know the output: {output}\n"
            "Work backwards—what input could’ve led to that?\n"
            "Figure out what had to happen in the code, and reverse it to get the input."
        ),
        "alias": (
            "Here's some {lang} code with two pointer variables:\n"
            "- Pointer A: '{pointer_1}'\n"
            "- Pointer B: '{pointer_2}'\n\n"
            "Do these pointers reference the same memory address? Answer \"Yes\" or \"No\".\n\n"
            "Code:\n"
            "```{lang}\n"
            "{code}\n"
            "```\n\n"
            "Function Input:\n"
            "{input}\n\n"
            "Question:\n"
            "Do '{pointer_1}' and '{pointer_2}' in (line {line_1}) point to the same memory location?\n\n"
            "Put your answer in <ans></ans> tags."
        ),
    },
    "pt2": {
        "statement_msg": (
            "{lang} code analysis. {shot} examples provided.\n"
            "Task: Predict value after highlighted statement (assignment, branch, or function calls) executes.\n"
            "Given: Full code, highlighted statement, pre-statement variables.\n\n"
            "----------------------------------------\n"
        ),
        "block_msg": (
            "{lang} code analysis. {shot} examples.\n"
            "Task: Evaluate highlighted statement given function inputs.\n"
            "Given: Full block, statement, inputs.\n\n"
            "----------------------------------------\n"
        ),
        "loop_msg": (
            "{lang} loop analysis. {shot} examples.\n"
            "Task: Analyze loop behavior/post loop variable value with given inputs.\n"
            "Given: Full loop, input values, questions.\n\n"
            "----------------------------------------\n"
        ),
        "input_output_msg": (
            "{lang} I/O mapping. {shot} examples.\n"
            "Task: Predict output from input or vice versa.\n"
            "Given: Full function, partial I/O data.\n\n"
            "----------------------------------------\n"
        ),
        "assignment": (
            "{lang} code:\n```{lang}\n{code}\n```\n"
            "Statement: {statement}\n"
            "Pre-execution variables: {variables}\n"
            "Answer using <ans></ans> tags, Do not include any extra information."
        ),
        "branch": (
            "{lang} code:\n```{lang}\n{code}\n```\n"
            "Branch: {statement}\n"
            "Condition variables: {variables}\n"
            "Execute? <ans>Yes/No</ans>, Answer using <ans></ans> tags, Do not include any extra information."
        ),
        "api": (
            "{lang} function call:\n```{lang}\n{code}\n```\n"
            "Call: {statement}\n"
            "Parameters: {variables}\n"
            "Return value: Answer using <ans></ans> tags, Do not include any extra information."
        ),
        "block": (
            "{lang} block:\n```{lang}\n{code}\n```\n"
            "Selected Statement: {statement}\n"
            "Code Inputs: {inputs}\n"
            "Expected output of selected statement: Answer using <ans></ans> tags, Do not include any extra information."
        ),
        "output": (
            "{lang} function:\n```{lang}\n{code}\n```\n"
            "Input: {input}\n"
            "Required Output: Answer using <ans></ans> tags, Do not include any extra information."
        ),
        "input": (
            "{lang} function:\n```{lang}\n{code}\n```\n"
            "Output: {output}\n"
            "Required input: Answer using <ans></ans> tags, Do not include any extra information."
        ),
        "loop_iteration": (
            "{lang} loop:\n```{lang}\n{code}\n```\n"
            "Question: {question}\n"
            "Answer using <ans></ans> tags, Do not include any extra information."
        ),
        "loop_body": (
            "{lang} loop body:\n```{lang}\n{code}\n```\n"
            "Question: {question}\n"
            "Answer using <ans></ans> tags, Do not include any extra information."
        ),
        "assignment_cot": (
            "1. RHS evaluation using {variables}\n"
            "2. Assign to LHS\n"
            "3. Result: <ans></ans>"
        ),
        "branch_cot": (
            "1. Evaluate '{statement}'\n"
            "2. With {variables}\n"
            "3. Condition is <ans>True/False</ans>"
        ),
        "api_cot": (
            "1. Process {variables}\n"
            "2. Execute {statement}\n"
            "3. Return <ans></ans>"
        ),
        "block_cot": (
            "1. Analyze the {statement} and inputs {input} of the code block.\n"
            "2. Execute line\n"
            "3. New state: <ans></ans>"
        ),
        "loop_iteration_cot": (
            "1. Evaluate initialized variables\n"
            "2. Check condition\n"
            "3. Final state: <ans></ans>"
        ),
        "loop_body_cot": (
            "1. Check current values\n"
            "2. Apply operations\n"
            "3. Output: <ans></ans>"
        ),
        "post_loop_analysis_cot": (
            "1. Exit reason\n"
            "2. Evaluate final values\n"
            "3. Determine variable value after loop\n"
            "4. Result: <ans></ans>"
        ),
        "output_cot": (
            "1. Transform {input}\n"
            "2. Through all operations\n"
            "3. Final output: <ans></ans>."
        ),
        "input_cot": (
            "1. Reverse-engineer {output}\n"
            "2. Required input: <ans></ans>."
        ),
        "alias": (
            "Here's some {lang} code with two pointer variables:\n"
            "- Pointer A: {pointer_1}\n"
            "- Pointer B: {pointer_2}\n\n"
            "Do these pointers reference the same memory address? Answer \"Yes\" or \"No\".\n\n"
            "Code:\n"
            "```{lang}\n"
            "{code}\n"
            "```\n\n"
            "Function Input:\n"
            "{input}\n\n"
            "Question:\n"
            "Do {pointer_1} and {pointer_2} in (line {line_1}) point to the same memory location?\n\n"
            "Put your answer in <ans></ans> tags."
        ),
    },
    "pt3": {
        "statement_msg": (
            "Let's analyze {lang} code together. Consider:\n"
            "- What does the given statement (assignment, branch, or function calls) accomplish?\n"
            "- How do current variable values affect execution?\n"
            "- What transformation should occur?\n\n"
            "{shot} illustrative examples follow:\n\n"
            "----------------------------------------\n"
        ),
        "block_msg": (
            "Examine this {lang} block carefully:\n"
            "- What role does the highlighted statement play?\n"
            "- How do the function inputs propagate to this point?\n"
            "- What state change should we expect?\n\n"
            "{shot} guided examples:\n\n"
            "----------------------------------------\n"
        ),
        "loop_msg": (
            "Let's investigate this {lang} loop:\n"
            "- What's the loop's termination condition?\n"
            "- How do variables transform each iteration?\n"
            "- What's the final state after completion?\n\n"
            "{shot} loop walkthroughs:\n\n"
            "----------------------------------------\n"
        ),
        "input_output_msg": (
            "Analyze this {lang} function's behavior:\n"
            "- How do inputs flow through the operations?\n"
            "- What patterns connect inputs to outputs?\n"
            "- Can we reconstruct missing I/O elements?\n\n"
            "{shot} demonstration cases:\n\n"
            "----------------------------------------\n"
        ),
        "assignment": (
            "Consider this {lang} assignment:\n```{lang}\n{code}\n```\n"
            "Given these pre-existing values:\n{variables}\n"
            "1. What does the right-hand side evaluate to?\n"
            "2. What memory location does this modify?\n"
            "3. Final value: <ans></ans>, Answer using <ans></ans> tags, Do not include any extra information."
        ),
        "branch": (
            "Evaluate this {lang} branch:\n```{lang}\n{code}\n```\n"
            "With these variable states:\n{variables}\n"
            "1. How does '{statement}' evaluate?\n"
            "2. Does this warrant branch execution?\n"
            "3. Verdict: <ans>Yes/No</ans>, Answer using <ans></ans> tags, Do not include any extra information."
        ),
        "api": (
            "Examine this {lang} function call:\n```{lang}\n{code}\n```\n"
            "Parameters provided:\n{variables}\n"
            "1. What's the function's essential purpose?\n"
            "2. How do parameters transform within it?\n"
            "3. Expected return: <ans></ans>, Answer using <ans></ans> tags, Do not include any extra information."
        ),
        "block": (
            "Study this {lang} code block:\n```{lang}\n{code}\n```\n"
            "Given inputs:{inputs}\n"
            "1. What's the statement's '{statement}' role in the block?\n"
            "2. How do inputs affect this specific operation?\n"
            "3. Statement's state after execution: <ans></ans>, Answer using <ans></ans> tags, Don't print any extra information."
        ),
        "output": (
            "Trace this {lang} function's execution:\n```{lang}\n{code}\n```\n"
            "Starting with inputs:\n{input}\n"
            "1. What's the critical transformation path?\n"
            "2. Where does data converge to the output?\n"
            "3. Final result: <ans></ans>, Answer using <ans></ans> tags, Don't print any extra information."
        ),
        "input": (
            "Reverse-engineer this {lang} function:\n```{lang}\n{code}\n```\n"
            "Observed output:\n{output}\n"
            "1. What intermediate states must have existed?\n"
            "2. What input conditions satisfy this output?\n"
            "3. Required input: <ans></ans>, Answer using <ans></ans> tags, Don't print any extra information."
        ),
        "loop_iteration": (
            "Analyze the given loop's behavior:\n```{lang}\n{code}\n```\n"
            "Question: {question}\n"
            "1. What's the loop's invariant?\n"
            "2. How does each iteration advance the state?\n"
            "3. Resolution: <ans></ans>, Answer using <ans></ans> tags, Don't print any extra information."
        ),
        "loop_body": (
            "Inspect this {lang} loop's internals:\n```{lang}\n{code}\n```\n"
            "Question: {question}\n"
            "1. What variables are mutated in the body?\n"
            "2. How does this affect the next iteration?\n"
            "3. Answer: <ans></ans>, Answer using <ans></ans> tags, Don't print any extra information."
        ),
        "post_loop_analysis": (
            "Evaluate this {lang} loop's final state:\n```{lang}\n{code}\n```\n"
            "Question: {question}\n"
            "1. Why did the loop terminate?\n"
            "2. What will be the value of the variable after loop terminates?\n"
            "3. Conclusion: <ans></ans>, Answer using <ans></ans> tags, Don't print any extra information."
        ),
        "assignment_cot": (
            "Guided assignment analysis:\n"
            "1. Right-hand side components: {variables}\n"
            "2. Evaluation steps for '{statement}'\n"
            "3. Memory update consequence\n"
            "Conclusion: <ans></ans>."
        ),
        "branch_cot": (
            "Branch condition investigation:\n"
            "1. Sub-expressions in '{statement}'\n"
            "2. Truth table with {variables}\n"
            "3. Control flow implication\n"
            "Decision: <ans>Yes/No</ans>."
        ),
        "api_cot": (
            "Function call breakdown:\n"
            "1. Parameter mapping: {variables}\n"
            "2. Function's operational transform\n"
            "3. Return value derivation\n"
            "Result: <ans></ans>."
        ),
        "block_cot": (
            "Block execution trace:\n"
            "1. Analyze the selected statement {statement} and input {input} progpagation of the funciton\n"
            "2. Statement's computational role\n"
            "3. Calculate what would be the value after statement's execution.\n"
            "Output: <ans></ans>."
        ),
        "loop_iteration_cot": (
            "Loop execution analysis:\n"
            "1. Initialization state\n"
            "2. Condition evaluation pattern\n"
            "3. Termination logic\n"
            "Final answer: <ans></ans>."
        ),
        "loop_body_cot": (
            "Loop body inspection:\n"
            "1. Variable snapshot at iteration start\n"
            "2. Operation sequence analysis\n"
            "3. Post-iteration state\n"
            "Resolution: <ans></ans>."
        ),
        "output_cot": (
            "Output derivation path:\n"
            "1. Input decomposition: {input}\n"
            "2. Critical transformation stages\n"
            "3. Output assembly process\n"
            "Final value: <ans></ans>."
        ),
        "input_cot": (
            "Input reconstruction:\n"
            "1. Output structure analysis: {output}\n"
            "2. Reverse dataflow mapping\n"
            "3. Input constraints derivation\n"
            "Solution: <ans></ans>."
        )
    },
    "pt4": {
        "statement_msg": (
            "[DEBUG CONSOLE] Starting {lang} code analysis session\n"
            "Execution breakpoints will be set at highlighted statements(assignment, branch, or function calls)\n"
            "Current stack frame variables will be displayed\n"
            "{shot} sample debugging sessions:\n\n"
            "----------------------------------------\n"
        ),
        "block_msg": (
            "[DEBUGGER] Entering {lang} code block analysis mode\n"
            "Input parameters captured in scope of the function\n"
            "Stepping through execution flow\n"
            "{shot} block debugging examples:\n\n"
            "----------------------------------------\n"
        ),
        "loop_msg": (
            "[LOOP DEBUG] Beginning loop execution trace\n"
            "Iteration analysis enabled\n"
            "Variable watchpoints active\n"
            "{shot} loop debugging traces:\n\n"
            "----------------------------------------\n"
        ),
        "input_output_msg": (
            "[I/O ANALYSIS] Starting function I/O profiling\n"
            "Tracing data flow between boundaries\n"
            "Reconstruction mode enabled\n"
            "{shot} I/O debugging cases:\n\n"
            "----------------------------------------\n"
        ),
        "assignment": (
            "[BREAKPOINT] Line hit: {statement}\n"
            "Code context:\n```{lang}\n{code}\n```\n"
            "Current stack frame:\n{variables}\n"
            "Next step evaluation -> Put your prediction in <ans></ans> tags, Do not include any extra information."
        ),
        "branch": (
            "[CONDITIONAL BREAK] Branch statement encountered\n"
            "Code context:\n```{lang}\n{code}\n```\n"
            "Condition variables snapshot:\n{variables}\n"
            "Will branch execute? Put your prediction [Yes/No] in <ans></ans> tags, Do not include any extra information."
        ),
        "api": (
            "[FUNCTION CALL] Intercepted: {statement}\n"
            "Code context:\n```{lang}\n{code}\n```\n"
            "Parameter dump:\n{variables}\n"
            "Expected return -> Put your prediction in <ans></ans> tags, Do not include any extra information."
        ),
        "block": (
            "[SCOPE ENTER] Block execution started\n"
            "Code context:\n```{lang}\n{code}\n```\n"
            "Selected Statement:{statement}\n"
            "Input registers:{inputs}\n"
            "Statement evaluation -> Put your prediction in <ans></ans> tags, Don't print any extra information."
        ),
        "output": (
            "[EXIT POINT] Function output analysis\n"
            "Code context:\n```{lang}\n{code}\n```\n"
            "Input arguments:\n{input}\n"
            "Return value -> Put your prediction in <ans></ans> tags, Don't print any extra information."
        ),
        "input": (
            "[REVERSE DEBUG] Output reconstruction mode\n"
            "Code context:\n```{lang}\n{code}\n```\n"
            "Observed output:\n{output}\n"
            "Required input -> Put your prediction in <ans></ans> tags, Don't print any extra information."
        ),
        "loop_iteration": (
            "[LOOP TRACE] Iteration analysis\n"
            "Code context:\n```{lang}\n{code}\n```\n"
            "Debug query: {question}\n"
            "Loop evaluator -> Put your prediction in <ans></ans> tags, Don't print any extra information."
        ),
        "loop_body": (
            "[BODY INSPECT] Loop internals probe\n"
            "Code context:\n```{lang}\n{code}\n```\n"
            "Debug query: {question}\n"
            "State analysis -> Put your prediction in <ans></ans> tags, Don't print any extra information."
        ),
        "post_loop_analysis_cot": (
            "[FINAL STATE] Post-execution analysis\n"
            "1. Termination trigger\n"
            "2. Variable freeze frame\n"
            "3. Loop invariant verification\n"
            "4. Variable value after loop exits\n"
            "Outcome -> <ans></ans>."
        ),
        "assignment_cot": (
            "[STEP THROUGH] Assignment analysis\n"
            "1. Right-hand side evaluation\n"
            "2. Current variables: {variables}\n"
            "3. Memory write operation\n"
            "Result -> <ans></ans>."
        ),
        "branch_cot": (
            "[CONDITION STEP] Branch prediction\n"
            "1. Condition decomposition: {statement}\n"
            "2. Variable states: {variables}\n"
            "3. Branch taken prediction\n"
            "Verdict -> <ans>Yes/No</ans>."
        ),
        "api_cot": (
            "[CALL STACK] Function analysis\n"
            "1. Parameter binding: {variables}\n"
            "2. Execution trace\n"
            "3. Return value construction\n"
            "Result -> <ans></ans>."
        ),
        "block_cot": (
            "[BLOCK STEP] Scope analysis\n"
            "1. Analyze the statement {statement} and input {input}  of the code block\n"
            "2. Statement impact\n"
            "3. State modification\n"
            "Output -> <ans></ans>."
        ),
        "loop_iteration_cot": (
            "[ITER TRACE] Loop analysis\n"
            "1. Initialization snapshot\n"
            "2. Condition evaluation\n"
            "3. Termination state\n"
            "Resolution -> <ans></ans>."
        ),
        "loop_body_cot": (
            "[BODY STEP] Iteration analysis\n"
            "1. Pre-iteration state\n"
            "2. Operation sequence\n"
            "3. Post-iteration delta\n"
            "Analysis -> <ans></ans>."
        ),
        "output_cot": (
            "[DATAFLOW] Output derivation\n"
            "1. Input pipeline: {input}\n"
            "2. Transformation stages\n"
            "3. Final output assembly\n"
            "Result -> <ans></ans>."
        ),
        "input_cot": (
            "[REVERSE TRACE] Input reconstruction\n"
            "1. Output analysis: {output}\n"
            "2. Backward propagation\n"
            "3. Input requirements\n"
            "Solution -> <ans></ans>."
        )
    },
}
