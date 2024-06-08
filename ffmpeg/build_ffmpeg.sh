#!/bin/bash

###
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#      http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
###

#=========================================================================================================
# Program: build_ffmpeg.sh
#
# Ver         Date            Author          Comment
# =======     ===========     ===========     ==========================================
# V1.0.00     2018-12-27      DW              Build multimedia file converter 'FFmpeg' for SMS.
# V1.0.01     2019-04-23      DW              Specify to use Bourne shell explicitly to avoid compatibility
#                                             issue across different Linux/Unix systems.
# V1.0.02     2019-05-23      DW              Install pre-requisites utilities on all supported platforms.
# V1.0.03     2019-10-17      DW              Install pre-requisites utilities for CentOS 8.
# V1.0.04     2021-02-08      DW              Use variable 'FF_VER' to control download FFmpeg source code version. 
# V1.0.05     2021-08-30      DW              Use FFmpeg 4.4 as multimedia file converter, previous working version is 4.3.1.
# V2.0.00     2023-03-18      DW              - Adjust it to cooperate with Node.js helping programs, not Perl helping
#                                               programs anymore.
#                                             - Use FFmpeg 6.0 as multimedia file converter, previous working version is 4.4.
# V2.0.01     2024-04-26      DW              Use FFmpeg 7.0 as multimedia file converter, previous working version is 6.0.
#=========================================================================================================

echo ""
echo "Build FFmpeg..."
echo ""

echo "Build FFmpeg is starting... " > /tmp/build_ffmpeg.log
echo `date` >> /tmp/build_ffmpeg.log

#-- Ensure required utilities have installed before build FFmpeg --#
echo "Install required utilities"
v=`hostnamectl | grep "CentOS Stream 8" | wc -l`
if [[ "$v" -eq 1 ]]
then
  dnf -y install bzip2 >> /tmp/build_ffmpeg.log
fi

v=`hostnamectl | grep "Rocky Linux 8" | wc -l`
if [[ "$v" -eq 1 ]]
then
  dnf -y install bzip2 >> /tmp/build_ffmpeg.log
fi

v=`hostnamectl | grep "AlmaLinux 8" | wc -l`
if [[ "$v" -eq 1 ]]
then
  dnf -y install bzip2 >> /tmp/build_ffmpeg.log
fi

v=`hostnamectl | grep "Debian GNU/Linux" | wc -l`
if [[ "$v" -eq 1 ]]
then
  apt-get -y install bzip2 >> /tmp/build_ffmpeg.log
fi

v=`hostnamectl | grep "Ubuntu" | wc -l`
if [[ "$v" -eq 1 ]]
then
  apt-get -y install bzip2 >> /tmp/build_ffmpeg.log
fi
  
#-- Remember the FFmpeg stored 'home' --#
export FF_HOME=`pwd`
mkdir bin

#-- Check BUILD_PRELOAD variable --#
if [[ -v BUILD_PRELOAD ]]
then
  export BUILD_PRELOAD=$BUILD_PRELOAD
else
  export BUILD_PRELOAD=Y
fi  

#-- Step 1: Download FFmpeg source and required additional packages, and compile all additional packages. --#
echo ""
echo "================================================================="
echo "Download FFmpeg and required additional libraries, please wait..."
echo "================================================================="
echo ""
echo "Download FFmpeg"
#-- FFmpeg version number, it is used for commands below. Note: Previous working version is 6.0 --#
FF_VER="7.0"
#-- Download FFmpeg source code according to 'FF_VER' --#
curl -O https://ffmpeg.org/releases/ffmpeg-$FF_VER.tar.bz2 >> /tmp/build_ffmpeg.log
bzip2 -d ffmpeg-$FF_VER.tar.bz2 >> /tmp/build_ffmpeg.log
tar -xvf ffmpeg-$FF_VER.tar >> /tmp/build_ffmpeg.log
mv -fv ./ffmpeg-$FF_VER ./ffmpeg >> /tmp/build_ffmpeg.log
rm -f ffmpeg-$FF_VER.tar >> /tmp/build_ffmpeg.log

echo ""
echo "Download and compile libogg"
cd "$FF_HOME/ffmpeg"
curl -O https://ftp.osuosl.org/pub/xiph/releases/ogg/libogg-1.3.3.tar.gz >> /tmp/build_ffmpeg.log 
tar -xzvf libogg-1.3.3.tar.gz >> /tmp/build_ffmpeg.log
rm -f libogg-1.3.3.tar.gz >> /tmp/build_ffmpeg.log
cd libogg-1.3.3
./configure --prefix="$FF_HOME/ffmpeg" --disable-shared
make
make install
make distclean
cd "$FF_HOME"

echo ""
echo "Download and compile libvorbis"
cd "$FF_HOME/ffmpeg"
curl -O https://ftp.osuosl.org/pub/xiph/releases/vorbis/libvorbis-1.3.3.tar.gz >> /tmp/build_ffmpeg.log
tar -xzvf libvorbis-1.3.3.tar.gz >> /tmp/build_ffmpeg.log 
rm -f libvorbis-1.3.3.tar.gz >> /tmp/build_ffmpeg.log
cd libvorbis-1.3.3
./configure --prefix="$FF_HOME/ffmpeg" --with-ogg="$FF_HOME/ffmpeg" --disable-shared
make
make install
make distclean
cd "$FF_HOME" 

echo ""
echo "Download and compile opencore-amr"
cd "$FF_HOME/ffmpeg"
#-- Note: Since sourceforge use redirection for file download, so it must use this way to get this file. --#  
curl -L https://sourceforge.net/projects/opencore-amr/files/opencore-amr/opencore-amr-0.1.5.tar.gz > opencore-amr-0.1.5.tar.gz
tar -xzvf opencore-amr-0.1.5.tar.gz >> /tmp/build_ffmpeg.log
rm -f opencore-amr-0.1.5.tar.gz >> /tmp/build_ffmpeg.log
cd opencore-amr-0.1.5
./configure --prefix="$FF_HOME/ffmpeg" --disable-shared --bindir="$FF_HOME/bin"
make
make install
make distclean
cd "$FF_HOME"

echo ""
echo "Download and compile yasm"
cd "$FF_HOME/ffmpeg"
curl -O http://www.tortall.net/projects/yasm/releases/yasm-1.3.0.tar.gz >> /tmp/build_ffmpeg.log
tar -xzvf yasm-1.3.0.tar.gz >> /tmp/build_ffmpeg.log
rm -f yasm-1.3.0.tar.gz >> /tmp/build_ffmpeg.log
cd yasm-1.3.0
./configure --prefix="$FF_HOME/ffmpeg" --bindir="/usr/bin"
make
make install
make distclean
cd "$FF_HOME"

#-- Step 2: Build FFmpeg --#
echo ""
echo "============================"
echo "Build FFmpeg, please wait..."
echo "============================"
echo ""
cd "$FF_HOME/ffmpeg"
mkdir -p "$FF_HOME/ffmpeg/tmp"
chmod 777 "$FF_HOME/ffmpeg/tmp"
export TMPDIR="$FF_HOME/ffmpeg/tmp"
export PKG_CONFIG_PATH="$FF_HOME/ffmpeg/lib/pkgconfig"
m=`ls -l /usr/bin/yasm | wc -l`
if (test $m = 0)
then  
  #-- If 'yasm' is missing, apply option '--disable-x86asm' to bypass using yasm to build FFmpeg. --#    
  ./configure --prefix="$FF_HOME/ffmpeg" --extra-cflags="-I$FF_HOME/ffmpeg/include" --extra-ldflags="-L$FF_HOME/ffmpeg/lib" --bindir="/usr/bin" --extra-libs="-ldl" --enable-gpl --enable-nonfree --enable-version3 --enable-libopencore-amrnb --enable-libopencore-amrwb --enable-libvorbis --disable-x86asm
else  
  ./configure --prefix="$FF_HOME/ffmpeg" --extra-cflags="-I$FF_HOME/ffmpeg/include" --extra-ldflags="-L$FF_HOME/ffmpeg/lib" --bindir="/usr/bin" --extra-libs="-ldl" --enable-gpl --enable-nonfree --enable-version3 --enable-libopencore-amrnb --enable-libopencore-amrwb --enable-libvorbis
fi  
make
make install
make distclean
rm -rfv $TMPDIR
export TMPDIR=""
export PKG_CONFIG_PATH=""

#-- Step 3: House keeping --#
cd "$FF_HOME"
rm -rf ffmpeg
rm -rf bin

#-- Step 4: Configure SMS system setting for audio converter --#
f=`ls -l /usr/bin/ffmpeg | wc -l`
if (test $f = 1)
then
  if (test $BUILD_PRELOAD = 'N')
  then  
    cp -f ./add_converter_setting.js /www/sms2
    cd /www/sms2
    chmod +x ./add_converter_setting.js
    ./add_converter_setting.js
    rm -f ./add_converter_setting.js 
    cd $FF_HOME 
  fi  
else
  echo ""
  echo "****************************************************************************************"
  echo "Audio converter FFmpeg built process is failure, please check for it after installation."
  echo "****************************************************************************************"
  echo ""
  read -p "Press enter to continue..."
  
  if (test $BUILD_PRELOAD = 'N')
  then
    cp -f ../remove_converter_setting.js /www/sms2
    cd /www/sms2
    chmod +x ./remove_converter_setting.js
    ./remove_converter_setting.js
    rm -f ./remove_converter_setting.js
    cd $FF_HOME 
  fi  
fi  

