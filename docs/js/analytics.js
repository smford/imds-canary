/**
 * Google Analytics 4 (GA4) Integration for imds-canary documentation
 * Measurement ID: imds-canary
 */

(function () {
  'use strict';

  var GA_MEASUREMENT_ID = 'imds-canary';

  // Detect PWA / standalone display mode
  function getPWAMode() {
    if (window.matchMedia('(display-mode: standalone)').matches || window.navigator.standalone === true) {
      return 'standalone';
    }
    return 'browser';
  }

  // Safe wrapper around gtag so errors or ad blockers never break the documentation
  function trackEvent(eventName, params) {
    try {
      if (typeof window.gtag === 'function') {
        var enrichedParams = Object.assign(
          {
            pwa_mode: getPWAMode(),
            page_location: window.location.href,
            page_path: window.location.pathname + window.location.hash,
            timestamp: new Date().toISOString(),
          },
          params || {}
        );
        window.gtag('event', eventName, enrichedParams);
      }
    } catch (e) {
      // Intentionally swallowed to guarantee non-blocking execution
    }
  }

  function trackPageView(path) {
    trackEvent('page_view', {
      page_path: path || window.location.pathname + window.location.hash,
      page_title: document.title,
    });
  }

  function trackCopyCommand(commandText) {
    trackEvent('copy_code_snippet', {
      command: commandText ? commandText.substring(0, 100) : '',
    });
  }

  function trackDownload(fileName, url) {
    trackEvent('download_binary', {
      file_name: fileName,
      download_url: url,
    });
  }

  function trackSearch(query) {
    if (!query) return;
    trackEvent('search', {
      search_term: query.substring(0, 50),
    });
  }

  // Hook into SPA hash route changes
  window.addEventListener('hashchange', function () {
    trackPageView(window.location.pathname + window.location.hash);
  });

  // Track initial page load
  if (document.readyState === 'complete' || document.readyState === 'interactive') {
    trackPageView();
  } else {
    document.addEventListener('DOMContentLoaded', function () {
      trackPageView();
    });
  }

  // Attach event delegation for clicks on links, downloads, and copy buttons
  document.addEventListener('click', function (e) {
    var target = e.target;

    // Detect copy code buttons
    if (target.matches('.copy-code-btn, [data-copy-btn], .copy-btn') || target.closest('.copy-code-btn')) {
      var pre = target.closest('pre');
      var codeText = pre ? pre.innerText : '';
      trackCopyCommand(codeText.trim());
      return;
    }

    // Detect anchor tag clicks
    var anchor = target.closest('a');
    if (!anchor) return;

    var href = anchor.getAttribute('href') || '';
    if (href.indexOf('/releases/download/') !== -1 || href.match(/\.(tar\.gz|zip|rpm|deb)$/)) {
      var parts = href.split('/');
      var fileName = parts[parts.length - 1];
      trackDownload(fileName, href);
    } else if (href.indexOf('github.com') !== -1 && href.indexOf('/smford/imds-canary') === -1) {
      trackEvent('outbound_github_link', { url: href });
    }
  });

  // Expose global tracker helpers for custom script invocation
  window.imdsCanaryAnalytics = {
    trackEvent: trackEvent,
    trackPageView: trackPageView,
    trackCopyCommand: trackCopyCommand,
    trackDownload: trackDownload,
    trackSearch: trackSearch,
  };
})();
