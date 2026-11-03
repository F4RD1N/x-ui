'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.resolve(__dirname, '../../web/assets/js/util/native-clipboard.js'), 'utf8');
const content = JSON.stringify({remarks: 'Native client — نمونه', outbounds: [{protocol: 'fixture'}]}, null, 2);

function fixture(options = {}) {
    const state = {nodes: [], created: [], commands: [], writes: [], focus: [], inputSelections: [], restoredRanges: []};
    const oldRange = {cloneRange: () => ({savedRange: true})};
    const selection = {
        rangeCount: 1,
        getRangeAt: () => oldRange,
        removeAllRanges() { state.rangesCleared = (state.rangesCleared || 0) + 1; },
        addRange(range) { state.restoredRanges.push(range); },
    };
    const active = {
        isConnected: true,
        selectionStart: 2,
        selectionEnd: 6,
        selectionDirection: 'backward',
        focus(settings) {
            state.focus.push({element: 'original', settings});
            if (options.restoreFocusThrows) throw new Error('fixture focus rejected');
            document.activeElement = this;
        },
        setSelectionRange(...args) { state.inputSelections.push(args); },
    };
    const body = {
        appendChild(node) {
            if (options.appendThrows) throw new Error('fixture append rejected');
            state.nodes.push(node);
            node.parentNode = this;
        },
        removeChild(node) {
            if (options.removeThrows) throw new Error('fixture removeChild rejected');
            state.nodes.splice(state.nodes.indexOf(node), 1);
            node.parentNode = null;
        },
    };
    const document = {
        activeElement: active,
        body,
        getSelection: () => selection,
        createElement(tag) {
            assert.equal(tag, 'textarea');
            if (options.createThrows) throw new Error('fixture creation rejected');
            const node = {
                style: {}, attributes: {}, value: '', parentNode: null,
                setAttribute(name, value) { this.attributes[name] = value; },
                focus(settings) { state.focus.push({element: 'temporary', settings}); document.activeElement = this; },
                select() {
                    if (options.selectThrows) throw new Error('fixture selection rejected');
                    state.selectedText = this.value;
                },
                setSelectionRange(start, end) { state.temporarySelection = [start, end]; },
                remove() { state.nodes.splice(state.nodes.indexOf(this), 1); this.parentNode = null; },
            };
            state.created.push(node);
            return node;
        },
        execCommand(command) {
            state.commands.push(command);
            assert.equal(this, document);
            assert.equal(state.nodes[0].value, content);
            if (options.detachActive) active.isConnected = false;
            if (options.copyThrows) throw new Error('fixture copy rejected');
            return options.copyResult ?? true;
        },
    };
    const clipboard = {
        async writeText(value) {
            assert.equal(this, clipboard, 'clipboard method keeps its receiver');
            state.writes.push(value);
            if (options.secureThrows) throw new Error('fixture permission denied');
        },
    };
    const globals = {document, isSecureContext: options.secure === true};
    if (!options.noNavigator) globals.navigator = options.noClipboard ? {} : {clipboard};
    if (options.windowDocument) { delete globals.document; globals.window = {document}; }
    if (options.noDocument) { delete globals.document; delete globals.window; }
    const context = vm.createContext(globals);
    vm.runInContext(source, context);
    return {copy: context.NativeClipboard.copyText, state, active, document, selection, context};
}

function assertCleanAndRestored(f) {
    assert.equal(f.state.nodes.length, 0, 'no temporary DOM node remains');
    for (const node of f.state.created) assert.equal(node.value, '', 'temporary text is cleared');
    assert.equal(f.document.activeElement, f.active, 'prior element regains focus');
    assert.deepEqual(f.state.inputSelections, [[2, 6, 'backward']]);
    assert.equal(f.state.rangesCleared, 1);
    assert.equal(f.state.restoredRanges.length, 1);
    assert.equal(f.state.restoredRanges[0].savedRange, true);
}

test('secure clipboard success copies exact Unicode JSON without creating DOM nodes', async () => {
    const f = fixture({secure: true});
    assert.equal(await f.copy(content), true);
    assert.deepEqual(f.state.writes, [content]);
    assert.deepEqual(f.state.commands, []);
    assert.deepEqual(f.state.created, []);
    assert.deepEqual(f.state.focus, []);
});

test('secure clipboard rejection falls back and restores focus and both selections', async () => {
    const f = fixture({secure: true, secureThrows: true});
    assert.equal(await f.copy(content), true);
    assert.deepEqual(f.state.writes, [content]);
    assert.deepEqual(f.state.commands, ['copy']);
    assert.equal(f.state.selectedText, content);
    assert.deepEqual(f.state.temporarySelection, [0, content.length]);
    assertCleanAndRestored(f);
});

for (const [name, options] of [
    ['HTTP even when a clipboard property exists', {}],
    ['missing navigator', {noNavigator: true}],
    ['missing secure clipboard API', {secure: true, noClipboard: true}],
    ['window document fallback', {windowDocument: true, noNavigator: true}],
]) {
    test(name + ' uses the HTTP-compatible fallback', async () => {
        const f = fixture(options);
        assert.equal(await f.copy(content), true);
        assert.deepEqual(f.state.writes, []);
        assert.deepEqual(f.state.commands, ['copy']);
        assertCleanAndRestored(f);
    });
}

for (const [name, options] of [
    ['execCommand returns false', {copyResult: false}],
    ['execCommand throws', {copyThrows: true}],
    ['select throws', {selectThrows: true}],
    ['append throws', {appendThrows: true}],
    ['createElement throws', {createThrows: true}],
    ['secure and fallback copying both fail', {secure: true, secureThrows: true, copyResult: false}],
]) {
    test(name + ' reports failure and cleans up', async () => {
        const f = fixture(options);
        assert.equal(await f.copy(content), false);
        assertCleanAndRestored(f);
    });
}

test('removeChild failure uses node.remove without retaining text', async () => {
    const f = fixture({removeThrows: true});
    assert.equal(await f.copy(content), true);
    assertCleanAndRestored(f);
});

test('a detached original element is not focused or given an input selection', async () => {
    const f = fixture({detachActive: true});
    assert.equal(await f.copy(content), true);
    assert.equal(f.state.nodes.length, 0);
    assert.deepEqual(f.state.inputSelections, []);
    assert.equal(f.state.focus.filter(item => item.element === 'original').length, 0);
});

test('focus restoration failure does not falsify successful copying or prevent cleanup', async () => {
    const f = fixture({restoreFocusThrows: true});
    assert.equal(await f.copy(content), true);
    assert.equal(f.state.nodes.length, 0);
    assert.equal(f.state.created[0].value, '');
    assert.equal(f.state.restoredRanges.length, 1);
});

test('missing document or execCommand reports failure without throwing', async () => {
    assert.equal(await fixture({noDocument: true}).copy(content), false);
    const f = fixture();
    delete f.document.execCommand;
    assert.equal(await f.copy(content), false);
    assert.deepEqual(f.state.created, []);
});

test('an unsupported input selection does not prevent copying or focus restoration', async () => {
    const f = fixture();
    Object.defineProperty(f.active, 'selectionStart', {get() { throw new Error('unsupported input'); }});
    f.document.getSelection = () => { throw new Error('unsupported selection'); };
    assert.equal(await f.copy(content), true);
    assert.equal(f.document.activeElement, f.active);
    assert.deepEqual(f.state.inputSelections, []);
    assert.equal(f.state.nodes.length, 0);
});

test('non-string input is rejected without clipboard or DOM activity', async () => {
    const f = fixture({secure: true});
    for (const value of [undefined, null, {}, [], 1, true]) assert.equal(await f.copy(value), false);
    assert.deepEqual(f.state.writes, []);
    assert.deepEqual(f.state.created, []);
});
