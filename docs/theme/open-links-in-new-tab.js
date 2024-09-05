document.addEventListener("DOMContentLoaded", function() {
    const links = document.querySelectorAll("a[href^='http']");
    links.forEach(link => {
        link.setAttribute("target", "_blank");
    });
});
