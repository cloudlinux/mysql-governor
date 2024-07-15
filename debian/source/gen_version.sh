#!/bin/bash


changelog_line=`/usr/bin/head -1 ./debian/changelog`
g_verrel=`echo $changelog_line | /usr/bin/gawk '{ print $2 }' | /bin/sed 's/[)(]//g'`

g_verrel_arr=(${g_verrel//./ })
g_verrel_num=${#g_verrel_arr[@]}

case "$g_verrel_num" in
    2)
        # like "1.2-83" - use them all
        g_version_release="${g_verrel_arr[0]}.${g_verrel_arr[1]}"
    ;;

    3)
        # like "1.2-83.1" - use them all
        g_version_release="${g_verrel_arr[0]}.${g_verrel_arr[1]}.${g_verrel_arr[2]}"
    ;;

    5)
        # like "1.2-83.1672329728.115148" - use only first 2 fields
        g_version_release="${g_verrel_arr[0]}.${g_verrel_arr[1]}"
    ;;

    6)
        # like "1.2-83.1.1672329728.115148" - use only first 3 fields
        g_version_release="${g_verrel_arr[0]}.${g_verrel_arr[1]}.${g_verrel_arr[2]}"
    ;;

    *)
        # unknown format - use as it
        g_version_release="${g_verrel}"
    ;;
esac

echo -e "#ifndef VERSION_H_\n#define VERSION_H_\n#define GOVERNOR_CUR_VER \"${g_version_release}\"\n#define GOVERNOR_OS_UBUNTU2004 1\n#endif\n" > ./src/version.h
echo -e "GOVERNOR_CUR_VER=\"${g_version_release}\"\n" > ./install/scripts/dbgovernor_version.py

echo "gen_version.sh g_version_release:${g_version_release}"
echo "gen_version.sh g_verrel:${g_verrel}"
echo "gen_version.sh g_verrel_arr:${g_verrel_arr[@]}"
echo "gen_version.sh g_verrel_num:${g_verrel_num}"

echo "gen_version.sh version.h ==BEGIN"
cat ./src/version.h
echo "gen_version.sh version.h END=="
