document.addEventListener('DOMContentLoaded', function () {
    // Extract headings from the content
    const content = document.querySelector('#content');
    const sidebar = document.querySelector('#sidebar');
  
    const headings = content.querySelectorAll('h1, h2, h3, h4, h5, h6');
    const list = document.createElement('ul');
  
    headings.forEach(heading => {
      const id = heading.textContent.trim().toLowerCase().replace(/\s+/g, '-').replace(/[^\w-]/g, '');
      heading.id = id;
  
      const listItem = document.createElement('li');
      const anchor = document.createElement('a');
      anchor.href = `#${id}`;
      anchor.textContent = heading.textContent;
      listItem.appendChild(anchor);
      list.appendChild(listItem);
    });
  
    sidebar.appendChild(list);
  
    // Smooth scrolling for sidebar links
    sidebar.querySelectorAll('a').forEach(anchor => {
      anchor.addEventListener('click', function (e) {
        e.preventDefault();
        document.querySelector(this.getAttribute('href')).scrollIntoView({
          behavior: 'smooth'
        });
      });
    });
  });
  