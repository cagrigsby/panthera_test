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

        // First, create a nested structure of the headers
        headers.forEach(function (header) {
            const text = header.textContent.trim();
            const level = parseInt(header.tagName[1]);
            
            // Skip site title and subtitle
            if (text === "{{ site.title }}" || text === "{{ site.subtitle }}") {
                return;
            }

            const headerObj = {
                text: text,
                id: header.id,
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

        // Function to create the HTML for the TOC
        function createTocHTML(items, level = 1) {
            let html = '<ul class="toc-list" style="list-style: none;">';
            
            items.forEach(item => {
                const hasChildren = item.children && item.children.length > 0;
                html += `
                    <li>
                        <div class="toc-item">
                            ${hasChildren ? 
                                '<span class="toggle-btn" role="button" tabindex="0">▶</span>' : 
                                '<span class="toggle-btn-placeholder" style="width: 20px; display: inline-block;"></span>'
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

        // Add click handlers for toggle buttons
        document.querySelectorAll('.toggle-btn').forEach(button => {
            button.addEventListener('click', function(e) {
                console.log('Toggle button clicked'); // Debug log
                const listItem = this.closest('li');
                if (listItem) {
                    console.log('Found list item, toggling expanded class'); // Debug log
                    listItem.classList.toggle('expanded');
                }
                e.stopPropagation(); // Prevent event bubbling
            });

            // Add keyboard support
            button.addEventListener('keypress', function(e) {
                if (e.key =