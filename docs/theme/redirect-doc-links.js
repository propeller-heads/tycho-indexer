document.addEventListener("DOMContentLoaded", function() {
    const currentUrl = window.location.href;

    if (currentUrl.includes('/tycho-core/README.html')) {
        window.location.href = currentUrl.replace('/tycho-core/README.html', '/technical/tycho-core.html');
    }
    if (currentUrl.includes('/tycho-storage/README.html')) {
        window.location.href = currentUrl.replace('/tycho-storage/README.html', '/technical/tycho-storage.html');
    }
    if (currentUrl.includes('/tycho-indexer/README.html')) {
        window.location.href = currentUrl.replace('/tycho-indexer/README.html', '/technical/tycho-indexer.html');
    }
    if (currentUrl.includes('/tycho-client/README.html')) {
        window.location.href = currentUrl.replace('/tycho-client/README.html', '/technical/tycho-client.html');
    }
    if (currentUrl.includes('/tycho-client-py/README.html')) {
        window.location.href = currentUrl.replace('/tycho-client-py/README.html', '/technical/tycho-client-py.html');
    }
});
