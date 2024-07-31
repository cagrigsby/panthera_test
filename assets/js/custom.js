document.addEventListener("DOMContentLoaded", function() {
  const sidebarContent = document.getElementById('sidebar-content');
  const contentHeaders = document.querySelectorAll('#content h1, #content h2, #content h3, #content h4, #content h5');

  contentHeaders.forEach(header => {
    const listItem = document.createElement('li');
    const linkItem = document.createElement('a');

    linkItem.href = `#${header.id}`;
    linkItem.textContent = header.textContent;

    listItem.appendChild(linkItem);
    sidebarContent.appendChild(listItem);
  });
});
