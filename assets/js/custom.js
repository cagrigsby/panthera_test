document.addEventListener('DOMContentLoaded', function () {
    // Extract headings from the content
    const content = document.querySelector('#content');
    const sidebar = document.querySelector('#sidebar');
  
    if (!content || !sidebar) {
      console.error('Content or sidebar element not found');
      return;
    }
  
    const headings = content.querySelectorAll('h1, h2, h3, h4, h5, h6');
    if (headings.length === 0) {
      console.log('No headings found in content');
      return;
    }
  
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
  