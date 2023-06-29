set -e
function usage()
{
   cat << HEREDOC
   Usage: $(basename $0) [-h] [-r REPO] [-p]

   Example: $(basename $0) coolNewFeature -s -p
   Or:      $(basename $0) 0.1.10 -p

   If a tag is set will label the docker image with it.

   If the commit is not tagged, marks this release as a snapshot release (for testing)
   will append '-SNAPSHOT.[LAST-TAG].[GIT-HASH]' to the Docker TAG.

   optional arguments:
     -h, --help                show this help message and exit
     -r, --repository          which image repository to use
     -p, --push                if set, the image will also be pushed
   Git tags
   --------

   The current HEAD will be tagged and the tag will be pushed, unless -s option is given.
HEREDOC
}

# taken from https://cutecoder.org/software/detecting-apple-silicon-shell-script/
is_m1 ()
{
  arch_name="$(uname -m)"
  if [ "${arch_name}" = "x86_64" ]; then
      if [ "$(sysctl -in sysctl.proc_translated 2> /dev/null)" = "1" ]; then
          echo "1"
      else
          echo "0"
      fi
  elif [ "${arch_name}" = "arm64" ]; then
      echo "1"
  else
      echo "Unknown architecture: ${arch_name}"
      exit 1
  fi
}

docker_build ()
{
  _DOCKERFILE=$1
  shift
  _TAG=$1
  shift

  if [ "$(is_m1)" = "1" ]; then
    echo "Building docker image (for M1) from $_DOCKERFILE tagged as $_TAG"
    docker build --platform linux/amd64 -f "$_DOCKERFILE" -t "$_TAG" "$@" .
  else
    echo "Building docker image from $_DOCKERFILE tagged as $_TAG"
    docker build -f "$_DOCKERFILE" -t "$_TAG" "$@" .
  fi
}


snap ()
{
    echo "-SNAPSHOT.$(git rev-parse --short HEAD)"
}

REPOSITORY="827659017777.dkr.ecr.eu-central-1.amazonaws.com/propeller-searcher"

POSITIONAL=()
while [[ $# -gt 0 ]]
do
key="$1"
  case $key in
      -r|--repository)
      REPOSITORY=$2
      shift # past argument
      shift
      ;;
      -p|--push)
      PUSH="true"
      shift # past argument
      ;;
      -h|--help)
      usage; exit;
      shift # past argument
      ;;
      -s|--snapshot)
      SNAPSHOT="true"
      shift # past argument
      ;;
      *)    # unknown option
      POSITIONAL+=("$1") # save it in an array for later
      shift # past argument
      ;;
  esac
done
set -- "${POSITIONAL[@]}"

TAG=$(git describe --tags --contains 2>/dev/null|| true)

if [[ -z "$SNAPSHOT" ]]; then
  echo "Creating release $TAG"
else
  TAG=$(git describe --tags --abbrev=0)
  TAG="$TAG$(snap)"
  echo "Creating snapshot release $TAG"
fi

IMAGE_SPEC=$REPOSITORY:$TAG
docker_build "Dockerfile" "$IMAGE_SPEC"

if [[ -z "$PUSH" ]]; then
  echo "Will not push to the image registry."
else
  docker push $IMAGE_SPEC
fi

printf "\nCurrent docker tag:\n%s\n" "$IMAGE_SPEC"