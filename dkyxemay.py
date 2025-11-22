import streamlit as st
import gspread
from oauth2client.service_account import ServiceAccountCredentials
import pandas as pd
import json 

# =========================
# 1. KẾT NỐI GOOGLE SHEETS
# =========================

@st.cache_resource
def get_gsheet_client():
    # Lấy JSON service account từ secrets
    raw_sa = st.secrets["gcp_service_account"]

    # Nếu Boss đang lưu nguyên file JSON trong secrets (dạng chuỗi) thì cần parse
    if isinstance(raw_sa, str):
        try:
            sa_info = json.loads(raw_sa)
        except Exception as e:
            st.error("Không đọc được JSON trong gcp_service_account (secrets). Vui lòng kiểm tra lại.\n\nChi tiết: " + str(e))
            st.stop()
    else:
        # Trường hợp Boss cấu hình theo dạng [gcp_service_account] trong TOML,
        # st.secrets trả về dạng “dict-like”, dùng luôn được
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
    df = pd.DataFrame(data)
    return df

def find_column(df, candidates):
    """
    Tìm cột trong df theo danh sách tên gợi ý (không phân biệt hoa/thường).
    Trả về tên cột thực tế trong df nếu tìm thấy, ngược lại trả về None.
    """
    lower_map = {c.lower(): c for c in df.columns}
    for cand in candidates:
        if cand.lower() in lower_map:
            return lower_map[cand.lower()]
    return None


def get_worksheet():
    client = get_gsheet_client()
    spreadsheet_id = st.secrets["sheets"]["spreadsheet_id"]
    worksheet_name = st.secrets["sheets"]["worksheet_name"]

    sh = client.open_by_key(spreadsheet_id)
    ws = sh.worksheet(worksheet_name)
    return ws

# =========================
# 2. HÀM HỖ TRỢ
# =========================

def init_session_state():
    if "user" not in st.session_state:
        st.session_state.user = None   # {"username":..., "row_index":..., "data": {...}}
    if "page" not in st.session_state:
        st.session_state.page = "login"  # login / main

def login(username, password):
    df = load_users_df()

    if df.empty:
        st.error("Google Sheet không có dữ liệu user nào.")
        return False

    # Tự động nhận diện cột username / password
    username_col = find_column(df, ["username", "user", "tendangnhap", "ten_dang_nhap"])
    password_col = find_column(df, ["password", "matkhau", "pass"])

    if username_col is None or password_col is None:
        st.error(
            "Không tìm thấy cột username/password trong Google Sheet.\n\n"
            "Các tên cột chấp nhận được:\n"
            "- Username: username, user, tendangnhap, ten_dang_nhap\n"
            "- Password: password, matkhau, pass"
        )
        return False

    # Chuẩn hóa dữ liệu để so khớp: bỏ khoảng trắng, không phân biệt hoa/thường cho username
    username_series = (
        df[username_col]
        .astype(str)
        .str.strip()
        .str.lower()
    )
    password_series = (
        df[password_col]
        .astype(str)
        .str.strip()
    )

    input_username = username.strip().lower()
    input_password = password.strip()

    matches = df[
        (username_series == input_username) &
        (password_series == input_password)
    ]

    if matches.empty:
        # Debug nhẹ cho Boss (có thể bỏ sau này)
        # st.write("DEBUG usernames:", username_series.tolist())
        # st.write("DEBUG passwords:", password_series.tolist())
        return False

    row_idx = matches.index[0]
    user_row = matches.iloc[0].to_dict()

    st.session_state.user = {
        "username": df.loc[row_idx, username_col],
        "row_index": row_idx,
        "data": user_row,
    }
    st.session_state.page = "main"
    return True



def update_password(hoten, lop, namhoc, new_password, confirm_password):
    if st.session_state.user is None:
        st.error("Bạn chưa đăng nhập.")
        return

    df = load_users_df()
    row_idx = st.session_state.user["row_index"]
    row = df.iloc[row_idx]

    # Kiểm tra họ tên, lớp, năm học (so khớp cùng row)
    if (
        str(row.get("hoten", "")).strip().lower() != hoten.strip().lower()
        or str(row.get("lop", "")).strip().lower() != lop.strip().lower()
        or str(row.get("namhoc", "")).strip().lower() != namhoc.strip().lower()
    ):
        st.error("Họ tên / Lớp / Năm học không khớp với dữ liệu đã đăng ký.")
        return

    if new_password != confirm_password:
        st.error("Mật khẩu mới và xác nhận mật khẩu không trùng khớp.")
        return

    ws = get_worksheet()

    # df.index 0 tương ứng với hàng 2 trên sheet (hàng 1 là header)
    sheet_row_number = row_idx + 2

    header = ws.row_values(1)
    if "password" not in header:
        st.error("Không tìm thấy cột 'password' trong csdl.")
        return

    col_password = header.index("password") + 1
    ws.update_cell(sheet_row_number, col_password, new_password)

    # Xóa cache để lần load sau thấy dữ liệu mới
    load_users_df.clear()

    st.success("Đổi mật khẩu thành công!")
    st.session_state.user["data"]["password"] = new_password


def update_vehicle(ten_pt, loai_pt, bien_so):
    if st.session_state.user is None:
        st.error("Bạn chưa đăng nhập.")
        return

    df = load_users_df()
    row_idx = st.session_state.user["row_index"]
    ws = get_worksheet()

    sheet_row_number = row_idx + 2
    header = ws.row_values(1)

    columns_map = {
        "ten_phuong_tien": ten_pt,
        "loai_phuong_tien": loai_pt,
        "bien_so": bien_so,
    }

    for col_name, value in columns_map.items():
        if col_name in header:
            col_num = header.index(col_name) + 1
            ws.update_cell(sheet_row_number, col_num, value)

    load_users_df.clear()
    st.success("Lưu thông tin phương tiện thành công!")


def save_full_table(edited_df: pd.DataFrame):
    """
    Admin sửa bảng dữ liệu bằng data_editor rồi bấm 'Lưu thay đổi toàn bảng'.
    Hàm này cập nhật lại toàn bộ sheet (trừ dòng header).
    """
    ws = get_worksheet()
    header = ws.row_values(1)

    # Đảm bảo giữ đúng thứ tự cột như trên sheet
    cols_in_df = [c for c in header if c in edited_df.columns]
    missing_cols = [c for c in header if c not in edited_df.columns]

    full_df = pd.DataFrame()
    for c in header:
        if c in edited_df.columns:
            full_df[c] = edited_df[c]
        else:
            full_df[c] = ""

    values = full_df[header].astype(str).values.tolist()

    ws.update("A1", [header] + values)

    load_users_df.clear()
    st.success("Đã lưu toàn bộ thay đổi dữ liệu lên csdl.")

# =========================
# 3. GIAO DIỆN LOGIN
# =========================

def show_login_page():
    st.title("Đăng nhập hệ thống")
    st.write("Vui lòng đăng nhập bằng tài khoản đã lưu trên csdl.")

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

def show_admin_editor():
    st.subheader("Quản trị: Cập nhật / sửa toàn bộ dữ liệu")
    st.caption("Chỉ nên dùng với tài khoản admin. Mọi thay đổi sẽ ghi trực tiếp lên csdl.")

    df = load_users_df()
    edited_df = st.data_editor(
        df,
        num_rows="dynamic",
        use_container_width=True,
        key="admin_editor"
    )

    if st.button("💾 Lưu thay đổi toàn bảng"):
        save_full_table(edited_df)

def show_main_page():
    st.title("Hệ thống đăng ký phương tiện đến trường")

    user = st.session_state.user
    st.info(f"Xin chào, **{user['username']}**")

    # Nút đăng xuất
    if st.button("Đăng xuất"):
        st.session_state.user = None
        st.session_state.page = "login"

        # Dùng rerun phù hợp với phiên bản Streamlit
        if hasattr(st, "rerun"):
            st.rerun()
        elif hasattr(st, "experimental_rerun"):
            st.experimental_rerun()

    st.markdown("---")

    # ======= LẤY DỮ LIỆU HIỆN TẠI CỦA USER & DANH SÁCH LỚP / NĂM HỌC =======
    df = load_users_df()
    row_idx = user["row_index"]
    row = df.iloc[row_idx]

    # Giá trị hiện tại của user
    current_hoten = str(row.get("hoten", ""))
    current_lop = str(row.get("lop", ""))
    current_namhoc = str(row.get("namhoc", ""))

    # Danh sách lop và namhoc từ Google Sheet
    if "lop" in df.columns:
        lop_options = sorted([str(x) for x in df["lop"].dropna().unique().tolist()])
    else:
        lop_options = []

    if "namhoc" in df.columns:
        namhoc_options = sorted([str(x) for x in df["namhoc"].dropna().unique().tolist()])
    else:
        namhoc_options = []

    # Phòng trường hợp sheet chưa có dữ liệu, tránh lỗi selectbox rỗng
    if not lop_options:
        lop_options = [current_lop] if current_lop else ["Chưa có dữ liệu"]

    if not namhoc_options:
        namhoc_options = [current_namhoc] if current_namhoc else ["Chưa có dữ liệu"]

    # Xác định index mặc định cho selectbox
    default_lop_index = lop_options.index(current_lop) if current_lop in lop_options else 0
    default_namhoc_index = namhoc_options.index(current_namhoc) if current_namhoc in namhoc_options else 0

    # 4.1. Khối đổi mật khẩu
    st.subheader("Đổi mật khẩu")

    with st.form("change_password_form"):
        hoten = st.text_input("Họ và tên (đã đăng ký)", value=current_hoten)

        lop = st.selectbox(
            "Lớp (chọn từ danh sách)",
            options=lop_options,
            index=default_lop_index,
        )

        namhoc = st.selectbox(
            "Năm học (chọn từ danh sách)",
            options=namhoc_options,
            index=default_namhoc_index,
        )

        new_password = st.text_input("Mật khẩu mới", type="password")
        confirm_password = st.text_input("Xác nhận mật khẩu mới", type="password")

        submitted_pw = st.form_submit_button("Đổi mật khẩu")

        if submitted_pw:
            update_password(hoten, lop, namhoc, new_password, confirm_password)

    st.markdown("---")

    # 4.2. Khối đăng ký phương tiện
    st.subheader("Đăng ký / sửa thông tin phương tiện đến trường")

    vehicle_options = [
        "Xe gắn máy",
        "Xe máy điện",
        "Xe đạp điện",
        "Xe đạp",
        "Người nhà đưa đón",
        "Phương tiện khác",
    ]

    default_ten_pt = row.get("ten_phuong_tien", "")
    default_loai_pt = row.get("loai_phuong_tien", vehicle_options[0])
    default_bien_so = row.get("bien_so", "")

    with st.form("vehicle_form"):
        ten_pt = st.text_input("Tên phương tiện", value=default_ten_pt)
        loai_pt = st.selectbox(
            "Loại phương tiện",
            options=vehicle_options,
            index=vehicle_options.index(default_loai_pt) if default_loai_pt in vehicle_options else 0,
        )
        bien_so = st.text_input("Biển số phương tiện (có thể bỏ trống)", value=default_bien_so)

        submitted_vehicle = st.form_submit_button("Lưu thông tin")

        if submitted_vehicle:
            update_vehicle(ten_pt, loai_pt, bien_so)

    st.markdown("---")

    # 4.3. Nếu là admin → cho phép cập nhật/sửa toàn bộ dữ liệu
    if user["username"] == "admin":
        with st.expander("👑 Bảng dữ liệu (Admin có thể sửa trực tiếp)", expanded=False):
            show_admin_editor()



# =========================
# 5. MAIN
# =========================

def main():
    st.set_page_config(page_title="Đăng ký phương tiện đến Trường THPT Nguyễn Trãi", page_icon="🚲")
    init_session_state()

    if st.session_state.page == "login" or st.session_state.user is None:
        show_login_page()
    else:
        show_main_page()

if __name__ == "__main__":
    main()
