// toc.js
document.addEventListener("DOMContentLoaded", function () {
    const tocContainer = document.querySelector("#toc-container");
    const contentSection = document.querySelector(".pan-layout-content");

    if (tocContainer && contentSection) {
        const headers = contentSection.querySelectorAll("h1, h2, h3, h4, h5");
        let tocStructure = [];
        let currentH1 = null;
        let currentH2 = null;
        let currentH3 = null;
        let currentH4 = null;

        // Create nested structure of headers
        headers.forEach(function (header) {
            const text = header.textContent.trim();
            const level = parseInt(header.tagName[1]);
            
            // Skip site title and subtitle
            if (text === "{{ site.title }}" || text === "{{ site.subtitle }}") {
                return;
            }

            const headerObj = {
                text: text,
                id: header.id || createIdFromText(text),
                children: []
            };

            switch (level) {
                case 1:
                    currentH1 = headerObj;
                    tocStructure.push(currentH1);
                    currentH2 = null;
                    currentH3 = null;
                    currentH4 = null;
                    break;
                case 2:
                    if (currentH1) {
                        currentH2 = headerObj;
                        currentH1.children.push(currentH2);
                        currentH3 = null;
                        currentH4 = null;
                    }
                    break;
                case 3:
                    if (currentH2) {
                        currentH3 = headerObj;
                        currentH2.children.push(currentH3);
                        currentH4 = null;
                    }
                    break;
                case 4:
                    if (currentH3) {
                        currentH4 = headerObj;
                        currentH3.children.push(currentH4);
                    }
                    break;
                case 5:
                    if (currentH4) {
                        currentH4.children.push(headerObj);
                    }
                    break;
            }
        });

        // Helper function to create IDs for headers that don't have them
        function createIdFromText(text) {
            return text.toLowerCase()
                      .replace(/[^a-z0-9]+/g, '-')
                      .replace(/(^-|-$)/g, '');
        }

        // Function to create the HTML for the TOC
        function createTocHTML(items, level = 1) {
            if (!items.length) return '';
            
            let html = `<ul class="toc-list level-${level}">`;
            
            items.forEach(item => {
                const hasChildren = item.children && item.children.length > 0;
                html += `
                    <li class="toc-item-container">
                        <div class="toc-item ${hasChildren ? 'has-children' : ''}">
                            ${hasChildren ? 
                                '<button class="toggle-btn" aria-expanded="false">+</button>' : 
                                '<span class="toggle-placeholder"></span>'
                            }
                            <a href="#${item.id}" class="toc-link toc-h${level}">${item.text}</a>
                        </div>
                        ${hasChildren ? createTocHTML(item.children, level + 1) : ''}
                    </li>
                `;
            });
            
            html += '</ul>';
            return html;
        }

        // Render the initial TOC
        tocContainer.innerHTML = createTocHTML(tocStructure);

        // Function to toggle expansion
        function toggleExpansion(element) {
            const listItem = element.closest('.toc-item-container');
            const button = listItem.querySelector('.toggle-btn');
            if (button) {
                const isExpanded = button.getAttribute('aria-expanded') === 'true';
                
                // Toggle the expanded state
                button.setAttribute('aria-expanded', !isExpanded);
                button.textContent = isExpanded ? '+' : '-';
                
                // Toggle visibility of child list
                const childList = listItem.querySelector('.toc-list');
                if (childList) {
                    childList.style.display = isExpanded ? 'none' : 'block';
                }
            }
        }

        // Add click handlers for toggle buttons and items
        document.querySelectorAll('.toc-item.has-children').forEach(item => {
            // Handle clicks on the entire item
            item.addEventListener('click', function(e) {
                // Only toggle if clicking the item itself or the button
                // (not when clicking the link)
                if (!e.target.classList.contains('toc-link')) {
                    toggleExpansion(this);
                    e.preventDefault();
                    e.stopPropagation();
                }
            });

            // Add keyboard support for the button
            const button = item.querySelector('.toggle-btn');
            if (button) {
                button.addEventListener('keypress', function(e) {
                    if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        toggleExpansion(this);
                    }
                });
            }
        });

        // Initially hide all nested lists
        document.querySelectorAll('.toc-list:not(.level-1)').forEach(list => {
            list.style.display = 'none';
        });
    }
});