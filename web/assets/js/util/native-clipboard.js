/* Clipboard handling for native client exports, including panels served over HTTP. */
(() => {
    function rememberSelection(document) {
        const saved = {active: document.activeElement, input: null, selection: null, ranges: null};
        try {
            if (typeof saved.active?.selectionStart === 'number' && typeof saved.active?.selectionEnd === 'number') {
                saved.input = [saved.active.selectionStart, saved.active.selectionEnd, saved.active.selectionDirection];
            }
        } catch { /* Some input types do not expose a text selection. */ }
        try {
            const selection = document.getSelection?.();
            if (selection) {
                const ranges = [];
                for (let index = 0; index < selection.rangeCount; index++) {
                    ranges.push(selection.getRangeAt(index).cloneRange());
                }
                saved.selection = selection;
                saved.ranges = ranges;
            }
        } catch { /* Selection restoration is best effort. */ }
        return saved;
    }

    function restoreSelection(saved) {
        if (!saved) return;
        const active = saved.active;
        if (active?.isConnected !== false && typeof active?.focus === 'function') {
            try { active.focus({preventScroll: true}); }
            catch { try { active.focus(); } catch { /* The previous element may no longer accept focus. */ } }
            if (saved.input && typeof active.setSelectionRange === 'function') {
                try { active.setSelectionRange(...saved.input); } catch { /* The input may have changed type. */ }
            }
        }
        if (saved.selection && saved.ranges) {
            try {
                saved.selection.removeAllRanges();
                for (const range of saved.ranges) saved.selection.addRange(range);
            } catch { /* A previous selection may no longer belong to the document. */ }
        }
    }

    globalThis.NativeClipboard = Object.freeze({
        async copyText(text) {
            if (typeof text !== 'string') return false;
            try {
                const clipboard = globalThis.navigator?.clipboard;
                if (globalThis.isSecureContext === true && typeof clipboard?.writeText === 'function') {
                    await clipboard.writeText(text);
                    return true;
                }
            } catch { /* Denied secure clipboard access can still permit a user-initiated fallback. */ }

            const document = globalThis.document || globalThis.window?.document;
            if (!document?.body || typeof document.execCommand !== 'function') return false;
            let textarea;
            let saved;
            try {
                saved = rememberSelection(document);
                textarea = document.createElement('textarea');
                textarea.style.position = 'fixed';
                textarea.style.left = '-9999px';
                textarea.style.top = '0';
                textarea.style.fontSize = '16px';
                textarea.setAttribute('readonly', '');
                textarea.setAttribute('tabindex', '-1');
                textarea.value = text;
                document.body.appendChild(textarea);
                textarea.focus({preventScroll: true});
                textarea.select();
                textarea.setSelectionRange?.(0, text.length);
                return document.execCommand('copy') === true;
            } catch {
                return false;
            } finally {
                if (textarea) {
                    // Do not leave exported credentials in a detached DOM node.
                    textarea.value = '';
                    try { textarea.parentNode?.removeChild(textarea); }
                    catch { try { textarea.remove(); } catch { /* Cleanup must not mask the copy result. */ } }
                }
                restoreSelection(saved);
            }
        },
    });
})();
