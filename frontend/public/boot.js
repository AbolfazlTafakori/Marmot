// Runs before the app so the page never flashes the wrong direction or theme.
(function () {
  var get = function (k) {
    try {
      return window.localStorage.getItem('marmot.' + k);
    } catch (e) {
      return null;
    }
  };
  var root = document.documentElement;
  if (get('locale') === 'en') {
    root.lang = 'en';
    root.dir = 'ltr';
  }
  var theme = get('theme');
  var dark =
    theme === 'dark' || (theme !== 'light' && window.matchMedia('(prefers-color-scheme: dark)').matches);
  root.dataset.theme = dark ? 'dark' : 'light';
})();
