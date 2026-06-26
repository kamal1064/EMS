import os
import tempfile
from datetime import datetime
from flask import Response, current_app
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

def generate_pdf_response(pdf_sections, export_type):
    fd, temp_path = tempfile.mkstemp(suffix=".pdf")
    os.close(fd)
    
    # Setup document
    # For large tables, landscape is often better
    doc = SimpleDocTemplate(temp_path, pagesize=landscape(A4), rightMargin=30, leftMargin=30, topMargin=30, bottomMargin=30)
    
    elements = []
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'ReportTitle',
        parent=styles['Heading1'],
        fontSize=18,
        spaceAfter=14,
        textColor=colors.HexColor("#1E293B")
    )
    
    header_style = ParagraphStyle(
        'SectionHeader',
        parent=styles['Heading2'],
        fontSize=14,
        spaceBefore=12,
        spaceAfter=12,
        textColor=colors.HexColor("#3B82F6")
    )
    
    # Report Header
    report_title_map = {
        'all_employees': 'All Employees Report',
        'specific_employee': 'Employee Details Report',
        'all_part_time_workers': 'All Part-Time Workers Report',
        'specific_part_time_worker': 'Part-Time Worker Ledger'
    }
    
    title_text = report_title_map.get(export_type, 'EMS Export Report')
    elements.append(Paragraph(title_text, title_style))
    elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    elements.append(Spacer(1, 0.2 * inch))

    def format_cell_value(val, col_index, headers):
        if val is None:
            return ""
        
        # Check if column is money based on header
        header_name = headers[col_index].lower() if headers and col_index < len(headers) else ""
        is_money = any(term in header_name for term in ["salary", "amount", "advance", "deduction", "net", "price", "balance", "total"])
        
        if is_money and isinstance(val, (int, float)):
            return f"Rs. {val:,.2f}"
        
        return str(val)

    for section in pdf_sections:
        if not section['headers'] and not section['rows']:
            continue
            
        # Add section title
        if section['title']:
            elements.append(Paragraph(section['title'], header_style))
        
        table_data = []
        
        # Headers
        if section['headers']:
            table_data.append(section['headers'])
            
        # Rows
        if section['rows']:
            for row in section['rows']:
                formatted_row = [format_cell_value(val, i, section.get('headers', [])) for i, val in enumerate(row)]
                table_data.append(formatted_row)
                
        # Summary Row
        if section['summary_row']:
            formatted_summary = [format_cell_value(val, i, section.get('headers', [])) for i, val in enumerate(section['summary_row'])]
            table_data.append(formatted_summary)
            
        if not table_data:
            elements.append(Paragraph("No data available.", styles['Italic']))
            elements.append(Spacer(1, 0.2 * inch))
            continue

        # Create Table
        col_widths = None  # Auto compute
        t = Table(table_data, repeatRows=1 if section['headers'] else 0)
        
        # Table Style
        style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1E293B")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('TOPPADDING', (0, 0), (-1, 0), 10),
            
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('ALIGN', (0, 1), (-1, -1), 'LEFT'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#DDDDDD")),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('PADDING', (0,0), (-1,-1), 6)
        ])
        
        # Right align money columns
        if section['headers']:
            for i, header in enumerate(section['headers']):
                header_name = header.lower()
                if any(term in header_name for term in ["salary", "amount", "advance", "deduction", "net", "price", "balance", "total"]):
                    style.add('ALIGN', (i, 1), (i, -1), 'RIGHT')
        
        # Highlight summary row
        if section['summary_row']:
            last_idx = len(table_data) - 1
            style.add('FONTNAME', (0, last_idx), (-1, last_idx), 'Helvetica-Bold')
            style.add('BACKGROUND', (0, last_idx), (-1, last_idx), colors.HexColor("#F8FAFC"))
            
        t.setStyle(style)
        elements.append(t)
        elements.append(Spacer(1, 0.3 * inch))

    def add_page_number(canvas, doc):
        canvas.saveState()
        canvas.setFont('Helvetica', 9)
        canvas.setFillColor(colors.HexColor("#94A3B8"))
        canvas.drawString(30, 20, f"EMS Generated Report - Page {doc.page}")
        canvas.restoreState()

    doc.build(elements, onFirstPage=add_page_number, onLaterPages=add_page_number)
    
    filename = f"export_{export_type}_{datetime.now().strftime('%Y-%m-%d')}.pdf"

    def generate_and_delete():
        try:
            with open(temp_path, 'rb') as f:
                while chunk := f.read(8192):
                    yield chunk
        finally:
            try:
                os.remove(temp_path)
            except Exception as e:
                current_app.logger.error(f"Failed to delete temp file {temp_path}: {e}")

    return Response(
        generate_and_delete(),
        mimetype='application/pdf',
        headers={
            'Content-Disposition': f'attachment; filename="{filename}"'
        }
    )
