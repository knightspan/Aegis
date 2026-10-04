# Source from Git Bash: sets the JDK 17 / Ant / TSK environment used to build AEGIS.
# AEGIS_ROOT is the folder that holds tools/ (override it before sourcing if needed).
export AEGIS_ROOT="${AEGIS_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
export JAVA_HOME="$(cygpath -w "$AEGIS_ROOT/tools/jdk-17.0.20.1+1")"
export JDK_HOME="$JAVA_HOME"
export TSK_HOME="$(cygpath -w "$AEGIS_ROOT/working/sleuthkit-sleuthkit-4.15.0")"
export PATH="$AEGIS_ROOT/tools/jdk-17.0.20.1+1/bin:$AEGIS_ROOT/tools/apache-ant-1.10.15/bin:$PATH"
