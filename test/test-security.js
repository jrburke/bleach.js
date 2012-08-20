/**
 * Verify important security considerations.
 **/

var mocha = require('mocha')
  , bleach = require('../')
  , should = require('should');

var escapeOpts = {
  tags: ['img', 'span'],
};

var stripOpts = {
  tags: ['img', 'span'],
  strip: true,
};

var stripPruneOpts = {
  tags: ['img', 'span'],
  strip: true,
  prune: ['script'],
};

describe('bleach', function () {
  it('strips on* handlers when not whitelisted', function() {
    bleach.clean('<img onclick="evil">', escapeOpts)
      .should.equal('<img>');
  });

  // The sane thing to do with scripts is to prune them, but it
  it('escaping scripts', function() {
    bleach.clean('Be <script>evil, not</script> good!', escapeOpts)
      .should.equal('Be &lt;script&gt;evil, not&lt;/script&gt; good!');
  });

  it('stripping scripts', function() {
    bleach.clean('Be <script>evil, not</script> good!', stripOpts)
      .should.equal('Be evil, not good!');
  });

  it('pruning scripts', function() {
    bleach.clean('Be <script>evil, not</script> good!', stripPruneOpts)
      .should.equal('Be  good!');
  });

  it('sees through dumb parser tricks', function() {
    var t = '<scr<script></script>ipt type="text/javascript">alert("foo");</' +
            '<script></script>script<del></del>>';
    // this is what bleach actually expects:
    /*
    var e = '&lt;scr&lt;script&gt;&lt;/script&gt;ipt type="text/javascript"' +
              '&gt;alert("foo");&lt;/script&gt;script&lt;del&gt;&lt;/del&gt;' +
              '&gt;';
    */
    // but this is what jsdom actually provides:
    var e = '&lt;scr&gt;\n  &lt;script&gt;&lt;/script&gt;\nipt ' +
            'type="text/javascript"alert("foo");  &lt;script&gt;' +
            '&lt;/script&gt;\nscript  &lt;del&gt;&lt;/del&gt;\n&lt;/scr&gt;';
    // (Right now for other cases we let jsdom just cause failures because it's
    // obvious that the problem is trivial, but the above is impossible for
    // a human to scan.)
    bleach.clean(t, escapeOpts).should.equal(e);
  });
});
