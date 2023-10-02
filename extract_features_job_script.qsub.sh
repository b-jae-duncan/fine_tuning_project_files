#   This is the most basic QSUB file needed for this cluster.
#   Further examples can be found under /share/apps/examples
#   Most software is NOT in your PATH but under /share/apps
#
#   For further info please read http://hpc.cs.ucl.ac.uk
#   For cluster help email cluster-support@cs.ucl.ac.uk
#
#   NOTE hash dollar is a scheduler directive not a comment.


# These are flags you must include - Two memory and one runtime.
# Runtime is either seconds or hours:min:sec

#$ -l tmem=6G
#$ -l h_vmem=6G
#$ -l h_rt=00:45:00
#$ -t 0-868  

#These are optional flags but you probably want them in all jobs

#$ -S /bin/bash
#$ -wd /home/bduncan/jobs/output
#$ -j y
#$ -pe smp 10 
#$ -N APKARRAYJOB

#The code you want to run now goes here.

hostname
date

APK_DIR='xx'
OUTPUT_DIR='xx'
APK_META='xx'
APK_NAMES='xx'

INDEX=$(( $SGE_TASK_ID - 1))
source /share/apps/source_files/python/python-3.9.5.source

pip3 install -r requirements.txt

python3 ./extract_features_batch.py --apk_dir=${APK_DIR} --apk_meta=${APK_META} --apk_names_file=${APK_NAMES} --output_dir=${OUTPUT_DIR} --ncores=${NSLOTS} --sge_task_id=${INDEX}