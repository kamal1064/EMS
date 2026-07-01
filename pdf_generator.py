import os
import tempfile
import urllib.request
import shutil
from datetime import datetime
from flask import Response, current_app
from PIL import Image as PILImage
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image as RLImage
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

def download_temp_image(url):
    if not url:
        return None
    try:
        suffix = ".png" if ".png" in url.lower() else (".jpg" if ".jpg" in url.lower() else ".jpeg")
        # Download file to a temp file
        with urllib.request.urlopen(url, timeout=5) as response:
            fd, tmp_filename = tempfile.mkstemp(suffix=suffix)
            with os.fdopen(fd, 'wb') as tmp_file:
                shutil.copyfileobj(response, tmp_file)
            return tmp_filename
    except Exception as e:
        current_app.logger.error(f"Failed to download company logo: {e}")
        return None

def generate_pdf_response(pdf_sections, export_type, company_name=None, company_logo_url=None):
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
    
    # Company branding style
    company_name_style = ParagraphStyle(
        'CompanyBrandingName',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0F172A")
    )
    
    title_style = ParagraphStyle(
        'ReportTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=15,
        leading=18,
        spaceBefore=10,
        spaceAfter=4,
        textColor=colors.HexColor("#1E293B")
    )
    
    subtitle_style = ParagraphStyle(
        'ReportSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=11,
        spaceAfter=10,
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

    # Download and process logo if present
    logo_img = None
    downloaded_logo_path = None
    if company_logo_url:
        downloaded_logo_path = download_temp_image(company_logo_url)
        if downloaded_logo_path:
            try:
                with PILImage.open(downloaded_logo_path) as img:
                    w, h = img.size
                # Limit height to 40pt, scale width proportionally
                max_h = 40.0
                scale = max_h / h
                scaled_w = w * scale
                # Limit width to 120pt
                max_w = 120.0
                if scaled_w > max_w:
                    scale = max_w / w
                    scaled_w = max_w
                    scaled_h = h * scale
                else:
                    scaled_h = max_h
                logo_img = RLImage(downloaded_logo_path, width=scaled_w, height=scaled_h)
            except Exception as e:
                current_app.logger.error(f"Error processing logo in ReportLab: {e}")
                
    # Build company branding header
    header_title_cell = Paragraph(company_name or "WorkNest EMS", company_name_style)
    if logo_img:
        # Logo and name side-by-side
        header_table = Table([[logo_img, header_title_cell]], colWidths=[130, printable_width - 130])
        header_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 0),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 0),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ]))
        elements.append(header_table)
    else:
        # Text only
        elements.append(header_title_cell)
        
    # Top divider line
    divider_table = Table([[""]], colWidths=[printable_width])
    divider_table.setStyle(TableStyle([
        ('LINEBELOW', (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
        ('TOPPADDING', (0, 0), (-1, -1), 2),
    ]))
    elements.append(divider_table)
    elements.append(Spacer(1, 5))
    
    # Report Title and Date
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
    elements.append(Paragraph(f"Generated On: {datetime.now().strftime('%d/%m/%Y %H:%M')}", subtitle_style))
    
    # Bottom divider line under title block
    divider2_table = Table([[""]], colWidths=[printable_width])
    divider2_table.setStyle(TableStyle([
        ('LINEBELOW', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
    ]))
    elements.append(divider2_table)
    elements.append(Spacer(1, 8))

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
    
    # Clean up downloaded logo temp file if it was created
    if downloaded_logo_path:
        try:
            os.remove(downloaded_logo_path)
        except Exception as e:
            current_app.logger.error(f"Failed to delete temp logo file {downloaded_logo_path}: {e}")
            
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
