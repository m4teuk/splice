# bash completion for spl. Thin wrapper: all logic lives in `spl __complete`.
# Enable: source this file (or drop it in a bash-completion completions dir).
_spl() {
    local cur out
    cur="${COMP_WORDS[COMP_CWORD]}"
    out="$(spl __complete "$COMP_CWORD" "${COMP_WORDS[@]}" 2>/dev/null)"
    case "$out" in
        __FILES__) COMPREPLY=( $(compgen -f -- "$cur") ); compopt -o filenames 2>/dev/null ;;
        __DIRS__)  COMPREPLY=( $(compgen -d -- "$cur") ); compopt -o filenames 2>/dev/null ;;
        *)         COMPREPLY=( $(compgen -W "$out" -- "$cur") ) ;;
    esac
}
complete -F _spl spl
