#compdef spl
# zsh completion for spl. Thin wrapper: all logic lives in `spl __complete`.
# Enable: put this file (named `_spl`) on your $fpath and `autoload -U compinit && compinit`.
_spl() {
    local out
    # zsh `words` is 1-indexed with words[1]=spl; CURRENT is the 1-indexed cursor
    # word. The helper wants a 0-indexed cword with words[0]=spl.
    out="$(spl __complete $((CURRENT - 1)) "${words[@]}" 2>/dev/null)"
    case "$out" in
        __FILES__) _files; return ;;
        __DIRS__)  _files -/; return ;;
        *)         compadd -- ${(f)out} ;;
    esac
}
_spl "$@"
