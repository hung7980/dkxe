import streamlit as st
import gspread
from oauth2client.service_account import ServiceAccountCredentials
import pandas as pd
import json

# =========================
# 1. KẾT NỐI CSDL
# =========================

@st.cache_resource
def get_gsheet_client():
    # Đọc service account từ secrets
    raw_sa = st.secrets["gcp_service_account"]

    # Nếu Boss lưu dạng JSON string trong secrets
    if isinstance(raw_sa, str):
        sa_info = json.loads(raw_sa)
    else:
        # Nếu lưu dạng [gcp_service_account] trong TOML
        sa_info = dict(raw_sa)

    scope = [
        "https://spreadsheets.google.com/feeds",
        "https://www.googleapis.com/auth/drive",
    ]
    creds = ServiceAccountCredentials.from_json_keyfile_dict(sa_info, scope)
    client = gspread.authorize(creds)
    return client


@st.cache_data(ttl=60)
def load_users_df():
    client = get_gsheet_client()
    spreadsheet_id = st.secrets["sheets"]["spreadsheet_id"]
    worksheet_name = st.secrets["sheets"]["worksheet_name"]

    sh = client.open_by_key(spreadsheet_id)
    ws = sh.worksheet(worksheet_name)

    data = ws.get_all_records()
    if not data:
        return pd.DataFrame()
    df = pd.DataFrame(data)
    return df


def get_worksheet():
    client = get_gsheet_client()
    spreadsheet_id = st.secrets["sheets"]["spreadsheet_id"]
    worksheet_name = st.secrets["sheets"]["worksheet_name"]

    sh = client.open_by_key(spreadsheet_id)
    ws = sh.worksheet(worksheet_name)
    return ws


def ensure_column(ws, col_name):
    """
    Đảm bảo cột col_name tồn tại trên CSDL.
    Trả về số thứ tự cột (1-based).
    Nếu chưa có thì tự thêm vào header (hàng 1).
    """
    header = ws.row_values(1)
    if col_name in header:
        return header.index(col_name) + 1
    else:
        col_num = len(header) + 1
        ws.update_cell(1, col_num, col_name)
        return col_num


# =========================
# 2. HÀM HỖ TRỢ
# =========================

def init_session_state():
    if "user" not in st.session_state:
        st.session_state.user = None  # {"username","row_index","full_name","first_login_done","data"}
    if "page" not in st.session_state:
        st.session_state.page = "login"
    if "show_change_pw" not in st.session_state:
        st.session_state.show_change_pw = False


def find_column(df, candidates):
    """
    Tìm cột trong df theo danh sách tên gợi ý (không phân biệt hoa/thường).
    Trả về tên cột thực tế trong df nếu tìm thấy, ngược lại None.
    """
    lower_map = {c.lower(): c for c in df.columns}
    for cand in candidates:
        if cand.lower() in lower_map:
            return lower_map[cand.lower()]
    return None


def login(username, password):
    df = load_users_df()

    if df.empty:
        st.error("CSDL không có dữ liệu người dùng.")
        return False

    # Tự nhận diện cột username / password
    username_col = find_column(df, ["username", "user", "tendangnhap", "ten_dang_nhap"])
    password_col = find_column(df, ["password", "matkhau", "pass"])

    if username_col is None or password_col is None:
        st.error(
            "Không tìm thấy cột username/password trong CSDL.\n\n"
            "Các tên cột chấp nhận được:\n"
            "- Username: username, user, tendangnhap, ten_dang_nhap\n"
            "- Password: password, matkhau, pass"
        )
        return False

    username_series = df[username_col].astype(str).str.strip().str.lower()
    password_series = df[password_col].astype(str).str.strip()

    input_username = username.strip().lower()
    input_password = password.strip()

    matches = df[(username_series == input_username) & (password_series == input_password)]

    if matches.empty:
        return False

    row_idx = matches.index[0]
    row = matches.iloc[0]

    # Họ tên
    hoten_col = find_column(df, ["hoten", "ho_ten", "ho ten", "name", "fullname"])
    if hoten_col is not None:
        full_name = str(row.get(hoten_col, "")).strip()
    else:
        full_name = str(row.get(username_col, "")).strip()

    # Cờ lần đăng nhập đầu tiên
    first_login_col = find_column(df, ["first_login_done", "da_doi_mk", "first_login"])
    if first_login_col is None:
        first_login_done = False
    else:
        flag_val = str(row.get(first_login_col, "")).strip().lower()
        first_login_done = flag_val in ["yes", "true", "1", "ok", "done", "x"]

    st.session_state.user = {
        "username": str(row.get(username_col, "")).strip(),
        "row_index": row_idx,
        "full_name": full_name,
        "first_login_done": first_login_done,
        "data": row.to_dict(),
    }
    st.session_state.page = "main"
    return True


def set_first_login_done(row_idx):
    """
    Ghi cờ đã hoàn thành đăng nhập lần đầu tiên (first_login_done = 'yes')
    lên CSDL.
    """
    ws = get_worksheet()
    col_num = ensure_column(ws, "first_login_done")
    sheet_row_number = row_idx + 2  # df index 0 tương ứng với dòng 2
    ws.update_cell(sheet_row_number, col_num, "yes")
    # Xoá cache để đọc lại có cột này
    load_users_df.clear()


def update_password_first_login(selected_lop, selected_namhoc, new_password, confirm_password):
    """
    Đổi mật khẩu:
    """
    if st.session_state.user is None:
        st.error("Bạn chưa đăng nhập.")
        return

    if not new_password or not confirm_password:
        st.error("Vui lòng nhập đầy đủ mật khẩu mới và xác nhận.")
        return

    if new_password != confirm_password:
        st.error("Mật khẩu mới và xác nhận mật khẩu không trùng khớp.")
        return

    df = load_users_df()
    row_idx = st.session_state.user["row_index"]
    if row_idx < 0 or row_idx >= len(df):
        st.error("Không tìm thấy người dùng trong dữ liệu.")
        return

    ws = get_worksheet()
    sheet_row_number = row_idx + 2  # df index 0 tương ứng với dòng 2 trên CSDL

    # Xác định cột password, lớp, năm học
    password_col_name = find_column(df, ["password", "matkhau", "pass"])
    lop_col_name = find_column(df, ["lop", "lớp", "tenlop", "ten_lop", "class"])
    namhoc_col_name = find_column(df, ["namhoc", "nam_hoc", "nam hoc"])

    if password_col_name is None:
        st.error("Không tìm thấy cột password trong CSDL.")
        return

    # Cập nhật mật khẩu
    pass_col_num = ensure_column(ws, password_col_name)
    ws.update_cell(sheet_row_number, pass_col_num, new_password)

    # Cập nhật lớp
    if lop_col_name is not None and selected_lop:
        lop_col_num = ensure_column(ws, lop_col_name)
        ws.update_cell(sheet_row_number, lop_col_num, selected_lop)

    # Cập nhật năm học
    if namhoc_col_name is not None and selected_namhoc:
        namhoc_col_num = ensure_column(ws, namhoc_col_name)
        ws.update_cell(sheet_row_number, namhoc_col_num, selected_namhoc)

    # Đặt cờ đã đăng nhập lần đầu
    set_first_login_done(row_idx)

    # Cập nhật lại session_state
    st.session_state.user["first_login_done"] = True
    st.session_state.user["data"]["password"] = new_password
    if lop_col_name is not None and selected_lop:
        st.session_state.user["data"][lop_col_name] = selected_lop
    if namhoc_col_name is not None and selected_namhoc:
        st.session_state.user["data"][namhoc_col_name] = selected_namhoc

    # Xoá cache để lần sau load lại dữ liệu mới
    load_users_df.clear()

    st.success("Đã cập nhật mật khẩu, lớp và năm học cho lần đăng nhập đầu tiên.")
    # Sau khi xong, cho rerun để chuyển sang màn hình đăng ký phương tiện
    if hasattr(st, "rerun"):
        st.rerun()
    elif hasattr(st, "experimental_rerun"):
        st.experimental_rerun()


def update_password_later(selected_lop, selected_namhoc, new_password, confirm_password):
    """
    Đổi mật khẩu cho các lần đăng nhập sau.
    """
    if st.session_state.user is None:
        st.error("Bạn chưa đăng nhập.")
        return

    if not new_password or not confirm_password:
        st.error("Vui lòng nhập đầy đủ mật khẩu mới và xác nhận.")
        return

    if new_password != confirm_password:
        st.error("Mật khẩu mới và xác nhận mật khẩu không trùng khớp.")
        return

    df = load_users_df()
    row_idx = st.session_state.user["row_index"]
    if row_idx < 0 or row_idx >= len(df):
        st.error("Không tìm thấy người dùng trong dữ liệu.")
        return

    ws = get_worksheet()
    sheet_row_number = row_idx + 2

    password_col_name = find_column(df, ["password", "matkhau", "pass"])
    lop_col_name = find_column(df, ["lop", "lớp", "tenlop", "ten_lop", "class"])
    namhoc_col_name = find_column(df, ["namhoc", "nam_hoc", "nam hoc"])

    if password_col_name is None:
        st.error("Không tìm thấy cột password trong CSDL.")
        return

    # Cập nhật mật khẩu
    pass_col_num = ensure_column(ws, password_col_name)
    ws.update_cell(sheet_row_number, pass_col_num, new_password)

    # Cập nhật lớp
    if lop_col_name is not None and selected_lop:
        lop_col_num = ensure_column(ws, lop_col_name)
        ws.update_cell(sheet_row_number, lop_col_num, selected_lop)

    # Cập nhật năm học
    if namhoc_col_name is not None and selected_namhoc:
        namhoc_col_num = ensure_column(ws, namhoc_col_name)
        ws.update_cell(sheet_row_number, namhoc_col_num, selected_namhoc)

    load_users_df.clear()

    st.session_state.user["data"]["password"] = new_password
    if lop_col_name is not None and selected_lop:
        st.session_state.user["data"][lop_col_name] = selected_lop
    if namhoc_col_name is not None and selected_namhoc:
        st.session_state.user["data"][namhoc_col_name] = selected_namhoc

    st.success("Đã cập nhật mật khẩu, lớp và năm học.")


def update_vehicle(ten_pt, loai_pt, bien_so):
    """
    Lưu TÊN PHƯƠNG TIỆN + LOẠI PHƯƠNG TIỆN + BIỂN SỐ vào cùng dòng của user.
    """
    if st.session_state.user is None:
        st.error("Bạn chưa đăng nhập.")
        return

    df = load_users_df()
    row_idx = st.session_state.user["row_index"]
    if row_idx < 0 or row_idx >= len(df):
        st.error("Không tìm thấy người dùng trong dữ liệu.")
        return

    ws = get_worksheet()
    sheet_row_number = row_idx + 2

    # Đảm bảo các cột tồn tại
    col_ten_pt = ensure_column(ws, "ten_phuong_tien")
    col_loai_pt = ensure_column(ws, "loai_phuong_tien")
    col_bien_so = ensure_column(ws, "bien_so")

    # Cập nhật dữ liệu
    ws.update_cell(sheet_row_number, col_ten_pt, ten_pt)
    ws.update_cell(sheet_row_number, col_loai_pt, loai_pt)
    ws.update_cell(sheet_row_number, col_bien_so, bien_so)

    load_users_df.clear()
    st.success("Lưu thông tin phương tiện thành công!")


# =========================
# 3. GIAO DIỆN LOGIN
# =========================

def show_login_page():
    st.title("Đăng nhập hệ thống đăng ký phương tiện")

    username = st.text_input("Tên đăng nhập (username)")
    password = st.text_input("Mật khẩu", type="password")

    if st.button("Đăng nhập"):
        if username.strip() == "" or password.strip() == "":
            st.error("Vui lòng nhập đầy đủ username và mật khẩu.")
        else:
            ok = login(username, password)
            if not ok:
                st.error("Sai username hoặc mật khẩu.")


# =========================
# 4. GIAO DIỆN SAU ĐĂNG NHẬP
# =========================

def show_main_page():
    df = load_users_df()
    user_info = st.session_state.user
    row_idx = user_info["row_index"]

    if row_idx < 0 or row_idx >= len(df):
        st.error("Không tìm thấy dữ liệu người dùng trong CSDL.")
        return

    row = df.iloc[row_idx]
    full_name = user_info.get("full_name", user_info["username"])
    first_login_done = user_info.get("first_login_done", False)

    # Thanh trên cùng: tiêu đề + họ tên + nút đăng xuất
    top_col1, top_col2, top_col3 = st.columns([3, 2, 1])
    with top_col1:
        st.title("Đăng ký phương tiện đến trường THPT Nguyễn Trãi")
    with top_col2:
        st.markdown(f"👤 **{full_name}**")
    with top_col3:
        if st.button("Đăng xuất"):
            st.session_state.user = None
            st.session_state.page = "login"
            if hasattr(st, "rerun"):
                st.rerun()
            elif hasattr(st, "experimental_rerun"):
                st.experimental_rerun()

    st.markdown("---")

    # Lấy thông tin lớp & năm học hiện tại
    lop_col_name = find_column(df, ["lop", "lớp", "tenlop", "ten_lop", "class"])
    namhoc_col_name = find_column(df, ["namhoc", "nam_hoc", "nam hoc"])

    current_lop = str(row.get(lop_col_name, "")).strip() if lop_col_name else ""
    current_namhoc = str(row.get(namhoc_col_name, "")).strip() if namhoc_col_name else ""

    # Danh sách LỚP từ sheet
    lop_options = []
    if lop_col_name is not None:
        lop_options = sorted(
            [str(x) for x in df[lop_col_name].dropna().unique().tolist()]
        )
    if not lop_options:
        if current_lop:
            lop_options = [current_lop]
        else:
            lop_options = ["101", "102", "111", "121"]
    default_lop_index = (
        lop_options.index(current_lop) if current_lop in lop_options else 0
    )

    # Danh sách NĂM HỌC từ sheet
    namhoc_options = []
    if namhoc_col_name is not None:
        namhoc_options = sorted(
            [str(x) for x in df[namhoc_col_name].dropna().unique().tolist()]
        )
    if not namhoc_options:
        namhoc_options = ["2024-2025", "2025-2026", "2026-2027"]

    default_namhoc_index = (
        namhoc_options.index(current_namhoc) if current_namhoc in namhoc_options else 0
    )

    # ========== A. LẦN ĐĂNG NHẬP ĐẦU TIÊN ==========
    if not first_login_done:
        st.subheader("Thiết lập tài khoản lần đầu")
        st.info(
            "Đây là lần đăng nhập đầu tiên của bạn. "
            "Vui lòng chọn **Lớp**, **Năm học** và đổi mật khẩu, sau đó bấm **Lưu**."
        )

        with st.form("first_login_form"):
            st.text_input("Họ và tên", value=full_name, disabled=True)

            selected_lop = st.selectbox(
                "Lớp",
                options=lop_options,
                index=default_lop_index,
            )

            selected_namhoc = st.selectbox(
                "Năm học",
                options=namhoc_options,
                index=default_namhoc_index,
            )

            new_password = st.text_input("Mật khẩu mới", type="password")
            confirm_password = st.text_input("Xác nhận mật khẩu mới", type="password")

            submitted_first = st.form_submit_button("Lưu")

            if submitted_first:
                update_password_first_login(selected_lop, selected_namhoc, new_password, confirm_password)

        # Chưa xong lần đăng nhập đầu thì KHÔNG cho vào phần phương tiện
        return

    # ========== B. CÁC LẦN ĐĂNG NHẬP SAU: THAY ĐỔI MẬT KHẨU / LỚP / NĂM HỌC ==========
    st.subheader("Thông tin tài khoản")

    col_pw1, col_pw2 = st.columns([1, 3])
    with col_pw1:
        if st.button("Thay đổi mật khẩu"):
            st.session_state.show_change_pw = not st.session_state.show_change_pw

    with col_pw2:
        if st.session_state.show_change_pw:
            with st.form("change_pw_form"):
                st.text_input("Họ và tên", value=full_name, disabled=True)

                selected_lop = st.selectbox(
                    "Lớp",
                    options=lop_options,
                    index=default_lop_index,
                    key="lop_change",
                )

                selected_namhoc = st.selectbox(
                    "Năm học",
                    options=namhoc_options,
                    index=default_namhoc_index,
                    key="namhoc_change",
                )

                new_pw = st.text_input("Mật khẩu mới", type="password")
                confirm_pw = st.text_input("Xác nhận mật khẩu mới", type="password")
                submitted_change = st.form_submit_button("Lưu thay đổi")

                if submitted_change:
                    update_password_later(selected_lop, selected_namhoc, new_pw, confirm_pw)

    st.markdown("---")

    # ========== C. ĐĂNG KÝ / SỬA THÔNG TIN PHƯƠNG TIỆN ==========
    st.subheader("Đăng ký / sửa thông tin phương tiện đến trường THPT Nguyễn Trãi")

    vehicle_options = [
        " ",
        "Xe gắn máy",
        "Xe máy điện",
        "Xe đạp điện",
        "Xe đạp",
        "Người nhà đưa đón",
        "Phương tiện khác",
    ]

    ten_pt_default = str(row.get("ten_phuong_tien", "")).strip()
    loai_pt_default = str(row.get("loai_phuong_tien", vehicle_options[0])).strip()
    bien_so_default = str(row.get("bien_so", "")).strip()

    with st.form("vehicle_form"):
        ten_pt = st.text_input("Tên phương tiện", value=ten_pt_default)
        loai_pt = st.selectbox(
            "Loại phương tiện",
            options=vehicle_options,
            index=vehicle_options.index(loai_pt_default)
            if loai_pt_default in vehicle_options
            else 0,
        )
        bien_so = st.text_input(
            "Biển số phương tiện (có thể bỏ trống)",
            value=bien_so_default,
        )

        submitted_vehicle = st.form_submit_button("Lưu thông tin phương tiện")

        if submitted_vehicle:
            update_vehicle(ten_pt, loai_pt, bien_so)


# =========================
# 5. MAIN
# =========================

def main():
    st.set_page_config(page_title="Đăng ký phương tiện đến trường THPT Nguyễn Trãi", page_icon="🚲")
    init_session_state()

    if st.session_state.page == "login" or st.session_state.user is None:
        show_login_page()
    else:
        show_main_page()


if __name__ == "__main__":
    main()
