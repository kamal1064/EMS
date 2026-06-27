import os
import tempfile
from datetime import datetime
from flask import Response, current_app
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

def generate_pdf_response(pdf_sections, export_type):
    fd, temp_path = tempfile.mkstemp(suffix=".pdf")
    os.close(fd)
    
    # Page dimensions: A4 Landscape = 841.89 x 595.27 points
    # Margins: 30pt left/right -> Printable Width = 781.89 pt (target 780 pt)
    doc = SimpleDocTemplate(
        temp_path,
        pagesize=landscape(A4),
        rightMargin=30,
        leftMargin=30,
        topMargin=30,
        bottomMargin=30
    )
    
    printable_width = 780.0
    elements = []
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'ReportTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        spaceAfter=4,
        textColor=colors.HexColor("#1E293B")
    )
    
    subtitle_style = ParagraphStyle(
        'ReportSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=12,
        spaceAfter=14,
        textColor=colors.HexColor("#64748B")
    )
    
    header_style = ParagraphStyle(
        'SectionHeader',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=16,
        spaceBefore=12,
        spaceAfter=8,
        textColor=colors.HexColor("#1E293B")
    )
    
    # Styles for table cells
    th_left = ParagraphStyle('TH_Left', fontName='Helvetica-Bold', fontSize=8.5, leading=11, textColor=colors.whitesmoke, alignment=0)
    th_center = ParagraphStyle('TH_Center', fontName='Helvetica-Bold', fontSize=8.5, leading=11, textColor=colors.whitesmoke, alignment=1)
    th_right = ParagraphStyle('TH_Right', fontName='Helvetica-Bold', fontSize=8.5, leading=11, textColor=colors.whitesmoke, alignment=2)
    
    td_left = ParagraphStyle('TD_Left', fontName='Helvetica', fontSize=8.5, leading=11, textColor=colors.HexColor("#1E293B"), alignment=0)
    td_center = ParagraphStyle('TD_Center', fontName='Helvetica', fontSize=8.5, leading=11, textColor=colors.HexColor("#1E293B"), alignment=1)
    td_right = ParagraphStyle('TD_Right', fontName='Helvetica', fontSize=8.5, leading=11, textColor=colors.HexColor("#1E293B"), alignment=2)
    
    ts_left = ParagraphStyle('TS_Left', fontName='Helvetica-Bold', fontSize=8.5, leading=11, textColor=colors.HexColor("#0F172A"), alignment=0)
    ts_right = ParagraphStyle('TS_Right', fontName='Helvetica-Bold', fontSize=8.5, leading=11, textColor=colors.HexColor("#0F172A"), alignment=2)

    report_title_map = {
        'all_employees': 'All Employees Report',
        'specific_employee': 'Employee Details Report',
        'all_part_time': 'All Part-Time Workers Report',
        'all_part_time_workers': 'All Part-Time Workers Report',
        'specific_part_time': 'Part-Time Worker Ledger',
        'specific_part_time_worker': 'Part-Time Worker Ledger'
    }
    
    title_text = report_title_map.get(export_type, 'EMS Export Report')
    elements.append(Paragraph(title_text, title_style))
    elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}", subtitle_style))

    def format_cell_value(val, col_index, headers):
        if val is None:
            return ""
        header_name = headers[col_index].lower() if headers and col_index < len(headers) else ""
        is_money = any(term in header_name for term in ["salary", "amount", "advance", "deduction", "net", "price", "balance", "total", "gross"])
        if is_money and isinstance(val, (int, float)):
            return f"Rs. {val:,.2f}"
        return str(val)

    def get_column_widths(headers):
        if not headers:
            return None
        n = len(headers)
        h_lower = [h.lower() for h in headers]
        
        # Exact matching for known specific tables
        if h_lower == ["working date", "client name", "delivery location", "slab quantity", "price per slab", "gross amount", "remaining balance"]:
            return [75, 165, 170, 60, 80, 110, 120]
            
        if h_lower == ["worker id", "worker name", "working date", "client name", "delivery location", "slab quantity", "price per slab", "gross amount", "remaining balance", "payment status"]:
            return [60, 90, 65, 110, 115, 50, 65, 75, 80, 70]
            
        if h_lower == ["worker id", "worker name", "total work amount", "total advances", "remaining balance", "payment status"]:
            return [80, 150, 140, 130, 140, 140]
            
        if h_lower == ["worker id", "worker name", "reference", "advance amount", "advance date", "advance notes"]:
            return [65, 110, 220, 100, 75, 210]

        if h_lower == ["employee id", "employee name", "month", "base salary", "present days", "gross salary", "total advances", "net salary", "payment status"]:
            return [75, 110, 65, 85, 65, 95, 95, 95, 95]
            
        # General proportional weighting fallback
        weights = []
        for h in h_lower:
            if any(term in h for term in ["client", "location", "reference", "notes"]):
                weights.append(3.0)
            elif any(term in h for term in ["name"]):
                weights.append(2.0)
            elif any(term in h for term in ["salary", "amount", "advance", "balance", "gross", "net", "total", "price"]):
                weights.append(1.4)
            elif any(term in h for term in ["date", "month", "status"]):
                weights.append(1.0)
            else:
                weights.append(1.0)
                
        total_weight = sum(weights)
        return [round((w / total_weight) * printable_width, 1) for w in weights]

    for section in pdf_sections:
        if not section.get('headers') and not section.get('rows'):
            continue
            
        if section.get('title'):
            elements.append(Paragraph(section['title'], header_style))
        
        headers = section.get('headers', [])
        rows = section.get('rows', [])
        summary_row = section.get('summary_row')
        
        table_data = []
        col_widths = get_column_widths(headers)
        
        # 1. Process Header Row
        if headers:
            header_cells = []
            for i, h in enumerate(headers):
                h_lower = h.lower()
                is_money = any(term in h_lower for term in ["salary", "amount", "advance", "deduction", "net", "price", "balance", "total", "gross"])
                style_to_use = th_right if is_money else (th_center if any(t in h_lower for t in ["date", "id", "status", "days", "quantity"]) else th_left)
                header_cells.append(Paragraph(h, style_to_use))
            table_data.append(header_cells)
            
        # 2. Process Data Rows
        if rows:
            for row in rows:
                row_cells = []
                for i, val in enumerate(row):
                    formatted_str = format_cell_value(val, i, headers)
                    h_lower = headers[i].lower() if i < len(headers) else ""
                    is_money = any(term in h_lower for term in ["salary", "amount", "advance", "deduction", "net", "price", "balance", "total", "gross"])
                    is_center = any(term in h_lower for term in ["date", "id", "status", "days", "quantity", "month"])
                    
                    style_to_use = td_right if is_money else (td_center if is_center else td_left)
                    row_cells.append(Paragraph(formatted_str, style_to_use))
                table_data.append(row_cells)
                
        # 3. Process Summary Row
        if summary_row:
            summary_cells = []
            for i, val in enumerate(summary_row):
                if val is None or val == "":
                    summary_cells.append("")
                else:
                    formatted_str = format_cell_value(val, i, headers)
                    h_lower = headers[i].lower() if i < len(headers) else ""
                    is_money = any(term in h_lower for term in ["salary", "amount", "advance", "deduction", "net", "price", "balance", "total", "gross"])
                    style_to_use = ts_right if is_money else ts_left
                    summary_cells.append(Paragraph(formatted_str, style_to_use))
            table_data.append(summary_cells)
            
        if not table_data:
            elements.append(Paragraph("No data available.", styles['Italic']))
            elements.append(Spacer(1, 0.2 * inch))
            continue

        t = Table(table_data, colWidths=col_widths, repeatRows=1 if headers else 0)
        
        t_style = [
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1E293B")),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 5),
            ('RIGHTPADDING', (0, 0), (-1, -1), 5),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ]
        
        if summary_row:
            last_idx = len(table_data) - 1
            t_style.append(('BACKGROUND', (0, last_idx), (-1, last_idx), colors.HexColor("#F1F5F9")))
            
        t.setStyle(TableStyle(t_style))
        elements.append(t)
        elements.append(Spacer(1, 0.25 * inch))

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
