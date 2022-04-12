```
export GOROOT=/usr/lib/go
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
export PATH="$PATH:/home/packer/.local/bin"

## grep aliases
alias grep="grep --color=auto"
alias igrep="grep -i"
alias vgrep="grep -v"
alias egrep="egrep --color=auto"
alias fgrep="fgrep --color=auto"
      
## List open ports
alias ports="netstat -tulanp"
      
## Extract file, example. "ex package.tar.bz2"
ex() {
  if [[ -f $1 ]]; then
    case $1 in
      *.tar.bz2) tar xjf $1 ;;
      *.tar.gz)  tar xzf $1 ;;
      *.bz2)     bunzip2 $1 ;;
      *.rar)     rar x $1 ;;
      *.gz)      gunzip $1  ;;
      *.tar)     tar xf $1  ;;
      *.tbz2)    tar xjf $1 ;;
      *.tgz)     tar xzf $1 ;;
      *.zip)     unzip $1 ;;
      *.Z)       uncompress $1 ;;
      *.7z)      7z x $1 ;;
      *)         echo $1 cannot be extracted ;;
    esac
  else
    echo $1 is not a valid file
  fi
  }
# ex() is copied from https://github.com/Raikia/Kali-Setup/blob/master/kali.py
      
# python aliases
alias py="python3"
alias py2="python2"
alias http-serv="python3 -m http.server"
      
# General Aliases
alias cl="clear"
```
