document.addEventListener("DOMContentLoaded", function() {
  console.log("DOM fully loaded and parsed");

  function createListItem(header) {
      var li = document.createElement("li");
      var a = document.createElement("a");
      a.textContent = header.textContent;
      a.href = "#" + header.id;
      li.appendChild(a);
      return li;
  }

  var content = document.querySelector(".content");
  if (!content) {
      console.log("Content area not found");
      return;
  }

  var sidebarMenu = document.getElementById("sidebar-menu");
  if (!sidebarMenu) {
      console.log("Sidebar menu not found");
      return;
  }

  var headers = content.querySelectorAll("h1, h2, h3, h4, h5");
  if (headers.length === 0) {
      console.log("No headers found in content");
  }

  headers.forEach(function(header) {
      console.log("Processing header: ", header.textContent);
      if (!header.id) {
          header.id = header.textContent.toLowerCase().replace(/ /g, "-");
          console.log("Assigned ID: ", header.id);
      }
      sidebarMenu.appendChild(createListItem(header));
  });

  console.log("Sidebar menu populated");
});