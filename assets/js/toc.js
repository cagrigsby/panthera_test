document.addEventListener("DOMContentLoaded", function() {
    console.log("DOM fully loaded and parsed. Starting TOC generation.");
  
    function generateTOC() {
      var contentArea = document.querySelector(".pan-layout-content");
      var tocContainer = document.getElementById("toc-container");
  
      if (!contentArea || !tocContainer) {
        console.error("Content area or TOC container not found.");
        return;
      }
  
      var toc = document.createElement("div");
      toc.className = "toc";
      
      var tocTitle = document.createElement("h2");
      tocTitle.textContent = "Table of Contents";
      toc.appendChild(tocTitle);
  
      var ul = document.createElement("ul");
  
      var headers = contentArea.querySelectorAll("h1, h2, h3, h4, h5, h6");
      if (headers.length === 0) {
        console.log("No headers found in content area.");
      }
  
      headers.forEach(function(header) {
        var level = parseInt(header.tagName.replace('H', ''), 10);
        var id = header.id || header.textContent.trim().replace(/\s+/g, '-').toLowerCase();
  
        if (!header.id) {
          header.id = id;
        }
  
        var li = document.createElement("li");
        li.className = "toc-level-" + level;
        
        var a = document.createElement("a");
        a.href = "#" + id;
        a.textContent = header.textContent;
  
        li.appendChild(a);
        ul.appendChild(li);
      });
  
      toc.appendChild(ul);
      tocContainer.appendChild(toc);
  
      console.log("TOC generated and added to the page.");
    }
  
    generateTOC();
  });
  