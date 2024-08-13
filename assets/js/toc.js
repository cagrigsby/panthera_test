document.addEventListener("DOMContentLoaded", function () {
  const tocContainer = document.querySelector("#toc-container");
  const contentSection = document.querySelector(".pan-layout-content");

  if (tocContainer && contentSection) {
      const headers = contentSection.querySelectorAll("h1, h2, h3, h4, h5");
      let tocHTML = "<ul>";

      headers.forEach(function (header) {
          let indent = "";
          let text = header.textContent.trim();
          
          // Skip site title and subtitle
          if (text === "{{ site.title }}" || text === "{{ site.subtitle }}") {
              return;
          }

          switch (header.tagName.toLowerCase()) {
              case "h2":
                  indent = "- ";
                  break;
              case "h3":
                  indent = "-- ";
                  break;
              case "h4":
                  indent = "--- ";
                  break;
              case "h5":
                  indent = "---- ";
                  break;
          }

          tocHTML += `<li><a href="#${header.id}">${indent}${text}</a></li>`;
      });

      tocHTML += "</ul>";
      tocContainer.innerHTML = tocHTML;
  }
});
