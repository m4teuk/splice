# fish completion for spl. Thin wrapper: all logic lives in `spl __complete`.
# Enable: copy to ~/.config/fish/completions/spl.fish
function __spl_complete
    set -l toks (commandline -opc)   # tokens before the cursor (toks[1] == spl)
    set -l cur (commandline -ct)     # the partial word under the cursor
    # 0-indexed cword with words[0]=spl: the count of preceding tokens.
    set -l out (spl __complete (count $toks) $toks $cur 2>/dev/null)
    if test "$out" = __FILES__ -o "$out" = __DIRS__
        __fish_complete_path $cur
        return
    end
    printf '%s\n' $out
end

# -f: suppress fish's default file completion; the helper decides everything.
complete -c spl -f -a '(__spl_complete)'
