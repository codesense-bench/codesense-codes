set -e

# Create dockerfiles
(cd infra/base-images/base-builder; docker build -t gcr.io/oss-fuzz-base/base-builder:trace-modeling .)
(cd infra/base-images/base-runner; docker build -t gcr.io/oss-fuzz-base/base-runner:trace-modeling .)

# Populate data
python scripts/get_all_project_languages.py c | sort > data/projects_c.txt

# Create environment
conda create --name oss-fuzz python=3.10 -y
conda activate oss-fuzz
pip install -r requirements.txt

# Clone the tracer tool
git clone --branch c-tracer https://github.com/Robin-Y-Ding/trace-modeling tools/trace-modeling
cd tools/trace-modeling/trace_collection_c_cpp/tests
make
