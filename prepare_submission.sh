# /**
#  * Copyright (C) 2022 Carnegie Mellon University
#  *
#  * This file is part of the HTTP course project developed for
#  * the Computer Networks course (15-441/641) taught at Carnegie
#  * Mellon University.
#  *
#  * No part of the HTTP project may be copied and/or distributed
#  * without the express permission of the 15-441/641 course staff.
#  */

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

echo "Preparing submission..."
echo "Make sure to commit all files that you want to submit."

cd $SCRIPT_DIR
git archive -o handin.tar.gz HEAD

echo "Upload handin.tar.gz to Gradescope."